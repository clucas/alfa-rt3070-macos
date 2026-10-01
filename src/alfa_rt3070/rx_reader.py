# SPDX-License-Identifier: GPL-2.0-only
# Adapted from wifit3/chips/rx_reader.py, commit 053645ff19a82b9aa8430c687cc502405e6afc4c.
# Modified for immediate USB buffer dispatch on 2026-09-30.

from __future__ import annotations

import logging
import time

from wifit3.chips.rx_reader import (
    DROP_LOG_PERIOD,
    MAX_BACKLOG,
    PAUSE_POLL,
    RxReaderThread,
)


logger = logging.getLogger(__name__)


class ImmediateRxReaderThread(RxReaderThread):
    """USB buffers already aggregate frames; a second batch window delays TCP ACKs."""

    def _run(self) -> None:
        consecutive_errors = 0
        try:
            while self._running:
                if self._pause_req.is_set():
                    self._paused.set()
                    time.sleep(PAUSE_POLL)
                    continue
                try:
                    buffer = self._read_once()
                except Exception as error:
                    consecutive_errors += 1
                    if self._is_fatal(error, consecutive_errors):
                        break
                    time.sleep(0.01)
                    continue
                consecutive_errors = 0
                if not self._running:
                    break
                if not buffer:
                    continue
                if self._bufs_produced - self._bufs_consumed >= MAX_BACKLOG:
                    self._dropped += 1
                    now = time.monotonic()
                    if now >= self._next_drop_log:
                        self._next_drop_log = now + DROP_LOG_PERIOD
                        logger.error("[%s] RX dropped, %d total (backlog full)",
                                     self._name, self._dropped)
                    continue
                self._bufs_produced += 1
                try:
                    self._loop.call_soon_threadsafe(self._dispatch_batch, [buffer])
                except RuntimeError:
                    self._bufs_produced -= 1
                    break
        finally:
            self._running = False
            if self._dropped:
                logger.error("[%s] RX reader stopped: %d buffers dropped total",
                             self._name, self._dropped)
