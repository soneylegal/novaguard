"""
NovaGuard — Edge Sniffer (Captura Scapy).

Agente de borda que captura tráfego DNS em tempo real usando Scapy.
Cada pacote DNS capturado é convertido em um dicionário leve e
passado ao callback registrado.

Requisitos:
  - Privilégios de root (ou CAP_NET_RAW)
  - Interface de rede com tráfego DNS (porta 53)

Uso:
  sudo python -m agent.sniffer --interface eth0
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import signal
import sys
from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger("novaguard.sniffer")


class DNSSniffer:
    """
    Sniffer DNS de alta performance usando Scapy.

    Captura pacotes na porta 53 (DNS queries) e invoca o callback
    registrado para cada pacote processado.
    """

    def __init__(
        self,
        interface: str = "eth0",
        callback: Callable[[dict[str, Any]], None] | None = None,
        agent_id: str | None = None,
    ):
        self.interface = interface
        self.callback = callback
        self.agent_id = agent_id or f"agent-{os.getpid()}"
        self._running = False
        self._packet_count = 0

    def start(self) -> None:
        """Inicia a captura de pacotes DNS."""
        try:
            # Import tardio — Scapy requer root e é pesado
            from scapy.all import DNS, DNSQR, IP, sniff
        except ImportError:
            logger.error("Scapy não instalado. Execute: pip install scapy")
            sys.exit(1)

        self._running = True
        logger.info(
            "╔══════════════════════════════════════════════════╗\n"
            "║       NovaGuard Edge Sniffer Starting...         ║\n"
            "╚══════════════════════════════════════════════════╝"
        )
        logger.info("Interface: %s | Agent ID: %s", self.interface, self.agent_id)

        def process_packet(packet):
            """Callback do Scapy — processa cada pacote DNS capturado."""
            if not self._running:
                return

            try:
                if packet.haslayer(DNS) and packet.haslayer(DNSQR):
                    query = packet[DNSQR]

                    # Extrai informações do pacote
                    domain = query.qname.decode("utf-8", errors="ignore").rstrip(".")
                    query_type = self._resolve_qtype(query.qtype)
                    source_ip = packet[IP].src if packet.haslayer(IP) else "unknown"
                    dest_ip = packet[IP].dst if packet.haslayer(IP) else "unknown"

                    log_entry = {
                        "timestamp": datetime.now(UTC).isoformat(),
                        "source_ip": source_ip,
                        "destination_ip": dest_ip,
                        "domain": domain.lower(),
                        "query_type": query_type,
                        "protocol": "DNS",
                        "agent_id": self.agent_id,
                    }

                    self._packet_count += 1
                    if self._packet_count % 100 == 0:
                        logger.info("Captured %d DNS packets", self._packet_count)

                    if self.callback:
                        self.callback(log_entry)

            except Exception as e:
                logger.warning("Error processing packet: %s", e)

        try:
            logger.info("Starting packet capture (filter: UDP port 53)...")
            sniff(
                iface=self.interface,
                filter="udp port 53",
                prn=process_packet,
                store=False,  # Não armazena pacotes em memória
                stop_filter=lambda _: not self._running,
            )
        except PermissionError:
            logger.error("Permissão negada. Execute com sudo ou configure CAP_NET_RAW.")
            sys.exit(1)
        except OSError as e:
            logger.error("Erro na interface '%s': %s", self.interface, e)
            sys.exit(1)

    def stop(self) -> None:
        """Para a captura de forma limpa."""
        self._running = False
        logger.info("Sniffer stopped. Total packets captured: %d", self._packet_count)

    @staticmethod
    def _resolve_qtype(qtype: int) -> str:
        """Converte o código numérico do query type DNS em string."""
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
        return types.get(qtype, f"TYPE{qtype}")


def _default_callback(log_entry: dict[str, Any]) -> None:
    """Callback padrão — imprime o log em JSON para stdout."""
    print(json.dumps(log_entry, indent=None))


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
        default=os.getenv("API_GATEWAY_URL", "http://localhost:8000/api/v1/ingest"),
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

    log_level = getattr(logging, os.getenv("LOG_LEVEL", "INFO").upper(), logging.INFO)
    logging.basicConfig(
        level=log_level,
        format="%(asctime)s │ %(levelname)-8s │ %(name)s │ %(message)s",
    )

    # Integração com BufferSender (backoff + SQLite fallback)
    from agent.buffer_sender import BufferSender

    sender = BufferSender(
        api_url=args.api_url,
        api_key=args.api_key,
        flush_interval=args.buffer_interval,
        flush_size=args.buffer_size,
        agent_id=args.agent_id or f"agent-{os.getpid()}",
    )

    sniffer = DNSSniffer(
        interface=args.interface,
        callback=sender.enqueue,
        agent_id=args.agent_id,
    )

    # Graceful shutdown
    def signal_handler(sig, frame):
        logger.info("Shutdown signal received...")
        sniffer.stop()
        sender.stop()
        sys.exit(0)

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Inicia o sender em thread separada
    sender.start()

    # Inicia a captura (bloqueante)
    sniffer.start()


if __name__ == "__main__":
    main()
