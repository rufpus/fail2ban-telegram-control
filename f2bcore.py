# SPDX-License-Identifier: MIT
"""Import-safe shared constants and SQLite connections; no worker/management imports."""
import contextlib
import logging
import os
from pathlib import Path
import sqlite3
import threading
from typing import Iterator

STATE = Path(os.environ.get('F2BT_STATE', '/var/lib/fail2ban-telegram-control'))
CONFIG = Path(os.environ.get('F2BT_CONFIG', '/etc/fail2ban-telegram-control/config.json'))
LOCK = threading.RLock()
LOG = logging.getLogger('fail2ban-telegram-control')
# Optional systemd Environment override; the JSON configuration stays unchanged.
DEFAULT_RETENTION_DAYS = 30
TELEGRAM_TEXT_LIMIT = 4096  # Conservative bound including HTML markup, in UTF-16 units.
OUTBOX_MAX_ATTEMPTS = 8  # Bound recovery traffic during a prolonged outage.
DEAD_LETTER_NOTICE_INTERVAL = 300  # Aggregate owner warnings, at most once per five minutes.
CAPTURE_SETTLE_SECONDS = 15  # Wait for asynchronous Fail2ban bantime increments.
COMMAND_TIMEOUT_SECONDS = 15  # Bound local command execution.
MAINTENANCE_INTERVAL_SECONDS = 15  # Reconcile state even without Telegram traffic.
CONFIRMATION_TTL_SECONDS = 120  # Short-lived destructive-action confirmation.
OUTBOX_BACKOFF_MAX_SECONDS = 300  # Upper retry delay during an outage.
COMMAND_MAX_AGE_SECONDS = 300  # Reject commands delayed by Telegram outages.
MAX_BAN_SECONDS = 35 * 86400  # Match the configured five-week safety cap.
DEADLINE_GRACE_SECONDS = 1  # Allow clock movement across the Fail2ban socket.
CALLBACK_TEXT_LIMIT = 190  # Leave room below Telegram's 200-character alert limit.
CAPTURE_LOG_LIMIT = 12000  # Bound log storage per Fail2ban event.
TIME_TOLERANCE_SECONDS = 0.01  # Ignore timestamp serialization round-off.
LOCAL_ADDRESS_CACHE_SECONDS = 15  # Refresh alongside firewall reconciliation.

@contextlib.contextmanager
def database(state: Path = STATE) -> Iterator[sqlite3.Connection]:
    con = sqlite3.connect(state / 'state.sqlite3', timeout=3)
    con.row_factory = sqlite3.Row
    try:
        with con:
            yield con
    finally:
        con.close()
