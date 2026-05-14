"""
NovaGuard — Buffer Sender (IPC via multiprocessing.Queue).

Processo autónomo de envio com resiliência total:
  1. Lê logs de uma multiprocessing.Queue (IPC seguro).
  2. Acumula em buffer de memória até flush_size ou flush_interval.
  3. Envia via HTTP POST para o API Gateway.
  4. Em caso de falha:
     a. Persiste os logs em SQLite local (fallback).
     b. Tenta re-enviar com Exponential Backoff (2s, 4s, 8s…).
  5. Ao reconectar, drena o SQLite antes de enviar novos logs.

Garantia: NENHUM log é perdido, mesmo com a API fora do ar por horas.
Encerramento: Ao receber a sentinela (None) na Queue, drena o que resta
e encerra de forma limpa em < 3 segundos.

Nota sobre ambientes virtuais (venv) + sudo:
Para executar com sudo preservando as bibliotecas do venv, use o binário
python completo: sudo /path/to/venv/bin/python -m agent.sniffer
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import time
from datetime import UTC, datetime
from multiprocessing import Queue
from typing import Any

logger = logging.getLogger("novaguard.buffer_sender")

try:
    import httpx
except ImportError:
    logger.error("A biblioteca 'httpx' não foi encontrada. Execute: pip install httpx")
    sys.exit(1)

# Máximo de backoff: 5 minutos
MAX_BACKOFF_SECONDS = 300
INITIAL_BACKOFF_SECONDS = 2

# Sentinela de paragem (valor que nunca é um log válido)
STOP_SENTINEL = None


class BufferSender:
    """
    Processo de envio que lê de uma multiprocessing.Queue.

    Não usa threads internamente — todo o I/O é sequencial dentro
    do seu próprio processo, eliminando problemas de GIL.
    """

    def __init__(
        self,
        queue: Queue,
        api_url: str,
        api_key: str,
        flush_interval: int = 5,
        flush_size: int = 1000,
        agent_id: str = "agent-unknown",
        sqlite_path: str | None = None,
    ):
        self.queue = queue
        self.api_url = api_url
        self.api_key = api_key
        self.flush_interval = flush_interval
        self.flush_size = flush_size
        self.agent_id = agent_id

        # Buffer em memória (single-process, sem locks)
        self._buffer: list[dict[str, Any]] = []
        self._batch_sequence = 0

        # SQLite fallback
        self._sqlite_path = sqlite_path or os.path.join(
            os.path.dirname(os.path.abspath(__file__)),
            f".novaguard_fallback_{agent_id}.db",
        )
        self._init_sqlite()

        # Backoff state
        self._current_backoff = INITIAL_BACKOFF_SECONDS
        self._api_healthy = True

        # HTTP client (reusa conexões)
        self._http_client: httpx.Client | None = None

        # Estatísticas
        self.stats = {
            "total_enqueued": 0,
            "total_sent": 0,
            "total_failed": 0,
            "total_recovered": 0,
            "batches_sent": 0,
        }

    # ── Main Loop (roda dentro do Process) ───────────────────────

    def run(self) -> None:
        """
        Loop principal — bloqueia até receber a sentinela.
        Projetado para rodar como target de multiprocessing.Process.
        """
        # Criar o httpx.Client aqui (dentro do processo filho)
        self._http_client = httpx.Client(
            timeout=5.0,
            follow_redirects=True,
            headers={
                "X-API-KEY": self.api_key,
                "Content-Type": "application/json",
            },
        )

        logger.info(
            "BufferSender started (PID=%d): interval=%ds, size=%d, api=%s",
            os.getpid(),
            self.flush_interval,
            self.flush_size,
            self.api_url,
        )

        # Tenta drenar o SQLite ao iniciar
        self._drain_sqlite()

        last_flush_time = time.monotonic()

        while True:
            # Calcula quanto tempo falta até o próximo flush periódico
            elapsed = time.monotonic() - last_flush_time
            wait_timeout = max(0.1, self.flush_interval - elapsed)

            try:
                item = self.queue.get(timeout=wait_timeout)
            except Exception:
                # Timeout — hora de flush periódico
                item = "__TIMEOUT__"

            if item is STOP_SENTINEL:
                logger.info("Sentinela recebida. Drenando buffer restante...")
                self._drain_queue_remaining()
                self._final_flush()
                break

            if item != "__TIMEOUT__":
                self._buffer.append(item)
                self.stats["total_enqueued"] += 1

                # Flush por tamanho
                if len(self._buffer) >= self.flush_size:
                    self._flush()
                    last_flush_time = time.monotonic()
                    continue

            # Flush por tempo
            if time.monotonic() - last_flush_time >= self.flush_interval:
                logger.debug(
                    "Flush loop: buffer_size=%d, api_healthy=%s",
                    len(self._buffer),
                    self._api_healthy,
                )
                self._flush()

                if self._api_healthy:
                    self._drain_sqlite()

                last_flush_time = time.monotonic()

        # Cleanup
        if self._http_client:
            self._http_client.close()
        logger.info("BufferSender stopped (PID=%d). Stats: %s", os.getpid(), self.stats)

    # ── Flush ────────────────────────────────────────────────────

    def _flush(self) -> None:
        """Envia o buffer atual como lote para a API."""
        if not self._buffer:
            return

        batch = self._buffer.copy()
        self._buffer.clear()
        self._batch_sequence += 1

        success = self._send_batch(batch)
        if not success:
            self._persist_to_sqlite(batch)

    def _final_flush(self) -> None:
        """Flush final com timeout agressivo para shutdown rápido."""
        if not self._buffer:
            return

        batch = self._buffer.copy()
        self._buffer.clear()
        self._batch_sequence += 1

        if not self._api_healthy:
            logger.warning(
                "API unhealthy — emergency bypass: persisting %d logs to SQLite.",
                len(batch),
            )
            self._persist_to_sqlite(batch)
            return

        # Timeout agressivo no flush final (3s) para encerrar rápido
        success = self._send_batch(batch, timeout=3.0)
        if not success:
            self._persist_to_sqlite(batch)

    def _drain_queue_remaining(self) -> None:
        """Drena todos os itens restantes da Queue após a sentinela."""
        drained = 0
        while True:
            try:
                item = self.queue.get_nowait()
                if item is not STOP_SENTINEL:
                    self._buffer.append(item)
                    self.stats["total_enqueued"] += 1
                    drained += 1
            except Exception:
                break
        if drained:
            logger.info("Drained %d remaining items from queue.", drained)

    # ── HTTP Send ────────────────────────────────────────────────

    def _send_batch(self, logs: list[dict[str, Any]], timeout: float = 5.0) -> bool:
        """
        Envia um lote de logs para o API Gateway via HTTP POST.

        Returns:
            True se o envio foi bem-sucedido (2xx).
        """
        payload = {
            "logs": logs,
            "agent_id": self.agent_id,
            "batch_sequence": self._batch_sequence,
        }

        try:
            start_time = time.perf_counter()
            response = self._http_client.post(
                self.api_url,
                json=payload,
                timeout=timeout,
            )
            elapsed = time.perf_counter() - start_time

            if response.status_code in (200, 202):
                self.stats["total_sent"] += len(logs)
                self.stats["batches_sent"] += 1
                self._current_backoff = INITIAL_BACKOFF_SECONDS
                self._api_healthy = True

                logger.info(
                    "Batch #%d sent in %.2fs: %d logs (status=%d)",
                    self._batch_sequence,
                    elapsed,
                    len(logs),
                    response.status_code,
                )
                return True
            else:
                logger.warning(
                    "Batch #%d rejected: status=%d, body=%s",
                    self._batch_sequence,
                    response.status_code,
                    response.text[:200],
                )
                self._escalate_backoff()
                return False

        except (httpx.ConnectError, httpx.TimeoutException, httpx.NetworkError) as e:
            logger.warning(
                "Batch #%d send failed (API unreachable): %s. Next retry in %ds.",
                self._batch_sequence,
                type(e).__name__,
                self._current_backoff,
            )
            self._escalate_backoff()
            return False

        except Exception as e:
            logger.error(
                "Batch #%d unexpected error: %s",
                self._batch_sequence,
                e,
                exc_info=True,
            )
            self._escalate_backoff()
            return False

    def _escalate_backoff(self) -> None:
        """Dobra o tempo de backoff até o máximo."""
        self._api_healthy = False
        self._current_backoff = min(
            self._current_backoff * 2,
            MAX_BACKOFF_SECONDS,
        )

    # ── SQLite Fallback ──────────────────────────────────────────

    def _init_sqlite(self) -> None:
        """Inicializa o banco SQLite local para fallback."""
        conn = sqlite3.connect(self._sqlite_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS pending_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                batch_data TEXT NOT NULL,
                created_at TEXT NOT NULL,
                retry_count INTEGER DEFAULT 0
            )
        """)
        conn.commit()
        conn.close()
        logger.debug("SQLite fallback initialized: %s", self._sqlite_path)

    def _persist_to_sqlite(self, logs: list[dict[str, Any]]) -> None:
        """Persiste logs não enviados no SQLite local."""
        try:
            conn = sqlite3.connect(self._sqlite_path)
            conn.execute(
                "INSERT INTO pending_logs (batch_data, created_at) VALUES (?, ?)",
                (
                    json.dumps(logs, default=str),
                    datetime.now(UTC).isoformat(),
                ),
            )
            conn.commit()
            conn.close()

            self.stats["total_failed"] += len(logs)
            logger.info(
                "Persisted %d logs to SQLite fallback (total pending: %d)",
                len(logs),
                self._count_sqlite_pending(),
            )
        except Exception as e:
            logger.error("SQLite persist failed: %s", e)

    def _drain_sqlite(self) -> None:
        """
        Tenta re-enviar logs pendentes do SQLite.
        Processa um batch de cada vez para não sobrecarregar a API.
        """
        try:
            conn = sqlite3.connect(self._sqlite_path)
            cursor = conn.execute("SELECT id, batch_data FROM pending_logs ORDER BY id ASC LIMIT 1")
            row = cursor.fetchone()

            if row is None:
                conn.close()
                return

            row_id, batch_data = row
            logs = json.loads(batch_data)

            if self._send_batch(logs):
                conn.execute("DELETE FROM pending_logs WHERE id = ?", (row_id,))
                conn.commit()
                self.stats["total_recovered"] += len(logs)
                logger.info(
                    "Recovered %d logs from SQLite. Remaining: %d",
                    len(logs),
                    self._count_sqlite_pending() - 1,
                )
            else:
                conn.execute(
                    "UPDATE pending_logs SET retry_count = retry_count + 1 WHERE id = ?",
                    (row_id,),
                )
                conn.commit()

            conn.close()
        except Exception as e:
            logger.error("SQLite drain failed: %s", e)

    def _count_sqlite_pending(self) -> int:
        """Conta o número de lotes pendentes no SQLite."""
        try:
            conn = sqlite3.connect(self._sqlite_path)
            cursor = conn.execute("SELECT COUNT(*) FROM pending_logs")
            count = cursor.fetchone()[0]
            conn.close()
            return count
        except Exception:
            return -1
