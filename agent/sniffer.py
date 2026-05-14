"""
NovaGuard — Edge Sniffer (Captura Scapy via multiprocessing).

Arquitectura IPC:
  - Processo Principal: orquestra lifecycle, gere sinais (SIGINT/SIGTERM).
  - Processo Scapy: captura pacotes DNS e envia para a Queue IPC.
  - Processo BufferSender: lê da Queue, acumula, envia para a API.

O Scapy e o httpx correm em processos separados, sem contenção de GIL.

Requisitos:
  - Privilégios de root (ou CAP_NET_RAW)
  - Interface de rede com tráfego DNS (porta 53)

Uso:
  sudo python -m agent.sniffer --interface eth0
"""

from __future__ import annotations

import argparse
import logging
import multiprocessing
import os
import signal
import sys
from datetime import UTC, datetime
from multiprocessing import Process, Queue

logger = logging.getLogger("novaguard.sniffer")


# ── Processo do Scapy (filho) ────────────────────────────────────


def _scapy_worker(
    interface: str,
    agent_id: str,
    queue: Queue,
    stop_event: multiprocessing.Event,
) -> None:
    """
    Processo dedicado à captura Scapy.

    Cada pacote DNS capturado é serializado como dict e colocado na Queue.
    Quando stop_event é setado, o stop_filter encerra o sniff().
    """
    # Re-configurar logging no processo filho
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    )
    child_logger = logging.getLogger("novaguard.sniffer.scapy")

    try:
        from scapy.all import DNS, DNSQR, IP, sniff
    except ImportError:
        child_logger.error("Scapy não instalado. Execute: pip install scapy")
        return

    packet_count = 0

    def process_packet(packet):
        nonlocal packet_count
        if stop_event.is_set():
            return

        try:
            if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                query = packet[DNSQR]

                domain = query.qname.decode("utf-8", errors="ignore").rstrip(".")
                qtype = query.qtype
                types = {
                    1: "A",
                    2: "NS",
                    5: "CNAME",
                    6: "SOA",
                    12: "PTR",
                    15: "MX",
                    16: "TXT",
                    28: "AAAA",
                    33: "SRV",
                    255: "ANY",
                }
                query_type = types.get(qtype, f"TYPE{qtype}")
                source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                dest_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"

                log_entry = {
                    "timestamp": datetime.now(UTC).isoformat(),
                    "source_ip": source_ip,
                    "destination_ip": dest_ip,
                    "domain": domain.lower(),
                    "query_type": query_type,
                    "protocol": "DNS",
                    "agent_id": agent_id,
                }

                queue.put(log_entry)
                packet_count += 1

                if packet_count % 100 == 0:
                    child_logger.info("Captured %d DNS packets", packet_count)

        except Exception as e:
            child_logger.warning("Error processing packet: %s", e)

    child_logger.info(
        "Scapy worker started (PID=%d): interface=%s",
        os.getpid(),
        interface,
    )

    try:
        sniff(
            iface=interface,
            filter="udp port 53",
            prn=process_packet,
            store=False,
            stop_filter=lambda _: stop_event.is_set(),
        )
    except PermissionError:
        child_logger.error("Permissão negada. Execute com sudo ou configure CAP_NET_RAW.")
    except OSError as e:
        child_logger.error("Erro na interface '%s': %s", interface, e)

    child_logger.info(
        "Scapy worker stopped (PID=%d). Total captured: %d",
        os.getpid(),
        packet_count,
    )


# ── Processo do BufferSender (filho) ─────────────────────────────


def _sender_worker(
    queue: Queue,
    api_url: str,
    api_key: str,
    flush_interval: int,
    flush_size: int,
    agent_id: str,
) -> None:
    """
    Processo dedicado ao envio HTTP.

    Lê da Queue, acumula, e faz flush para a API.
    """
    # Re-configurar logging no processo filho
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    )

    from agent.buffer_sender import BufferSender

    sender = BufferSender(
        queue=queue,
        api_url=api_url,
        api_key=api_key,
        flush_interval=flush_interval,
        flush_size=flush_size,
        agent_id=agent_id,
    )
    sender.run()


# ── Orquestrador (Processo Principal) ────────────────────────────


def main():
    """Entrypoint CLI do sniffer."""
    parser = argparse.ArgumentParser(
        description="NovaGuard DNS Edge Sniffer",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "-i",
        "--interface",
        default="eth0",
        help="Interface de rede para captura (default: eth0)",
    )
    parser.add_argument(
        "--agent-id",
        default=None,
        help="ID único do agente (default: agent-<PID>)",
    )
    parser.add_argument(
        "--api-url",
        default=os.getenv("API_GATEWAY_URL", "http://localhost:8000/api/v1/ingest/"),
        help="URL do API Gateway",
    )
    parser.add_argument(
        "--api-key",
        default=os.getenv("AGENT_API_KEY", "agent-key-alpha-001"),
        help="API Key para autenticação",
    )
    parser.add_argument(
        "--buffer-interval",
        type=int,
        default=int(os.getenv("BUFFER_FLUSH_INTERVAL", "5")),
        help="Intervalo de flush do buffer em segundos (default: 5)",
    )
    parser.add_argument(
        "--buffer-size",
        type=int,
        default=int(os.getenv("BUFFER_FLUSH_SIZE", "1000")),
        help="Tamanho máximo do buffer antes do flush (default: 1000)",
    )

    args = parser.parse_args()

    agent_id = args.agent_id or f"agent-{os.getpid()}"

    log_level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    )

    logger.info(
        "╔══════════════════════════════════════════════════╗\n"
        "║       NovaGuard Edge Sniffer Starting...         ║\n"
        "╚══════════════════════════════════════════════════╝"
    )
    logger.info("Interface: %s | Agent ID: %s", args.interface, agent_id)
    logger.info("API Target: %s", args.api_url)

    # ── IPC Queue ────────────────────────────────────────────────
    ipc_queue: Queue = Queue(maxsize=10000)
    stop_event = multiprocessing.Event()

    # ── Spawn processos filhos ───────────────────────────────────
    scapy_proc = Process(
        target=_scapy_worker,
        args=(args.interface, agent_id, ipc_queue, stop_event),
        name="novaguard-scapy",
        daemon=False,
    )

    sender_proc = Process(
        target=_sender_worker,
        args=(
            ipc_queue,
            args.api_url,
            args.api_key,
            args.buffer_interval,
            args.buffer_size,
            agent_id,
        ),
        name="novaguard-sender",
        daemon=False,
    )

    sender_proc.start()
    scapy_proc.start()

    logger.info(
        "Processes spawned: scapy(PID=%d), sender(PID=%d)",
        scapy_proc.pid,
        sender_proc.pid,
    )

    # ── Graceful Shutdown ────────────────────────────────────────
    shutdown_triggered = False

    def signal_handler(sig, frame):
        nonlocal shutdown_triggered
        if shutdown_triggered:
            logger.warning("Force exit (second signal).")
            sys.exit(1)
        shutdown_triggered = True

        sig_name = signal.Signals(sig).name
        logger.info("Signal %s received. Initiating graceful shutdown...", sig_name)

        # 1. Parar o Scapy (stop_filter irá encerrar o sniff)
        stop_event.set()

        # 2. Esperar o Scapy terminar (max 3s)
        scapy_proc.join(timeout=3.0)
        if scapy_proc.is_alive():
            logger.warning("Scapy process did not stop. Terminating.")
            scapy_proc.terminate()
            scapy_proc.join(timeout=1.0)

        # 3. Enviar sentinela para o Sender (drena e encerra)
        ipc_queue.put(None)

        # 4. Esperar o Sender drenar (max 5s)
        sender_proc.join(timeout=5.0)
        if sender_proc.is_alive():
            logger.warning("Sender process did not stop. Terminating.")
            sender_proc.terminate()
            sender_proc.join(timeout=1.0)

        logger.info("NovaGuard Edge Sniffer shut down cleanly.")
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # ── Esperar processos (bloqueante) ───────────────────────────
    try:
        scapy_proc.join()
        # Se o Scapy morrer por conta própria, fazer shutdown graceful
        if not shutdown_triggered:
            logger.info("Scapy process exited. Sending sentinel to sender...")
            ipc_queue.put(None)
            sender_proc.join(timeout=5.0)
    except KeyboardInterrupt:
        # Fallback se o signal_handler não conseguiu capturar
        if not shutdown_triggered:
            signal_handler(signal.SIGINT, None)


if __name__ == "__main__":
    main()
