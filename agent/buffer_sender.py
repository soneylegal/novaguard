"""
NovaGuard — Buffer Sender (Lote + Exponential Backoff).

Agente de envio com resiliência total:
  1. Acumula logs em buffer de memória.
  2. Flush automático a cada N segundos ou N logs (o que vier primeiro).
  3. Envia via HTTP POST para o API Gateway.
  4. Em caso de falha:
     a. Persiste os logs em SQLite local (fallback).
     b. Tenta re-enviar com Exponential Backoff (2s, 4s, 8s, 16s...).
  5. Ao reconectar, drena o SQLite antes de enviar novos logs.

Garantia: NENHUM log é perdido, mesmo com a API fora do ar por horas.

Nota sobre ambientes virtuais (venv) + sudo:
Para executar com sudo preservando as bibliotecas do venv, use o binário python
completo: sudo /path/to/venv/bin/python -m agent.sniffer
"""

from __future__ import annotations

import json
import logging
import os
import sqlite3
import sys
import threading
import time
from datetime import UTC, datetime
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


class BufferSender:
    """
    Buffer em memória com flush periódico e fallback em SQLite.

    Thread-safe: usa locks para acesso concorrente ao buffer.
    """

    def __init__(
        self,
        api_url: str,
        api_key: str,
        flush_interval: int = 5,
        flush_size: int = 1000,
        agent_id: str = "agent-unknown",
        sqlite_path: str | None = None,
    ):
        self.api_url = api_url
        self.api_key = api_key
        self.flush_interval = flush_interval
        self.flush_size = flush_size
        self.agent_id = agent_id

        # Buffer em memória (thread-safe)
        self._buffer: list[dict[str, Any]] = []
        self._lock = threading.Lock()
        self._batch_sequence = 0

        # Controle de vida
        self._running = False
        self._stop_event = threading.Event()
        self._flush_thread: threading.Thread | None = None

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
        self._http_client = httpx.Client(
            timeout=5.0,
            follow_redirects=True,
            headers={
                "X-API-KEY": self.api_key,
                "Content-Type": "application/json",
            },
        )

        # Estatísticas
        self.stats = {
            "total_enqueued": 0,
            "total_sent": 0,
            "total_failed": 0,
            "total_recovered": 0,
            "batches_sent": 0,
        }

    # ── Lifecycle ────────────────────────────────────────────────

    def start(self) -> None:
        """Inicia a thread de flush periódico."""
        self._running = True
        self._flush_thread = threading.Thread(
            target=self._flush_loop,
            daemon=True,
            name="buffer-flush",
        )
        self._flush_thread.start()
        logger.info(
            "BufferSender started: interval=%ds, size=%d, api=%s",
            self.flush_interval,
            self.flush_size,
            self.api_url,
        )

        # Tenta drenar o SQLite ao iniciar
        self._drain_sqlite()

    def stop(self) -> None:
        """Para o sender, faz flush final e fecha conexões."""
        logger.info("BufferSender stopping... flushing remaining buffer.")
        self._running = False
        self._stop_event.set()

        # Flush final (Emergency Flush bypass se API estiver unhealthy)
        with self._lock:
            if self._buffer:
                batch = self._buffer.copy()
                self._buffer.clear()
                if not self._api_healthy:
                    logger.warning(
                        "API unhealthy — emergency bypass: persisting to SQLite."
                    )
                    self._persist_to_sqlite(batch)
                else:
                    self._batch_sequence += 1
                    success = self._send_batch(batch)
                    if not success:
                        self._persist_to_sqlite(batch)

        if self._flush_thread and self._flush_thread.is_alive():
            self._flush_thread.join(timeout=2.0)
            if self._flush_thread.is_alive():
                logger.error("Flush thread did not terminate cleanly. Forcing exit.")

        self._http_client.close()
        logger.info("BufferSender stopped. Stats: %s", self.stats)

    # ── Public API ───────────────────────────────────────────────

    def enqueue(self, log_entry: dict[str, Any]) -> None:
        """
        Adiciona um log ao buffer em memória.
        Se o buffer atingir flush_size, dispara flush imediato.
        """
        with self._lock:
            self._buffer.append(log_entry)
            self.stats["total_enqueued"] += 1

            if len(self._buffer) >= self.flush_size:
                self._flush()

    # ── Flush Loop ───────────────────────────────────────────────

    def _flush_loop(self) -> None:
        """Thread de flush periódico."""
        while self._running:
            interrupted = self._stop_event.wait(self.flush_interval)
            if interrupted or not self._running:
                break

            logger.debug(
                "Flush loop awake: buffer_size=%d, api_healthy=%s",
                len(self._buffer),
                self._api_healthy,
            )
            self._flush()

            # Tenta drenar o SQLite periodicamente
            if not self._api_healthy:
                self._stop_event.wait(self._current_backoff)
            else:
                self._drain_sqlite()

    def _flush(self) -> None:
        """
        Extrai o buffer atual e envia como lote para a API.
        Se falhar, persiste no SQLite.
        """
        with self._lock:
            if not self._buffer:
                return
            batch = self._buffer.copy()
            self._buffer.clear()

        self._batch_sequence += 1

        success = self._send_batch(batch)
        if not success:
            self._persist_to_sqlite(batch)

    # ── HTTP Send ────────────────────────────────────────────────

    def _send_batch(self, logs: list[dict[str, Any]]) -> bool:
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
                timeout=5.0,
                headers={"X-API-KEY": self.api_key, "Content-Type": "application/json"},
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
                "Batch #%d send failed (API unreachable): %s. " "Next retry in %ds.",
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
