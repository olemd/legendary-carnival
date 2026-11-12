"""Tell systemd that the daemon is up (sd_notify READY=1), for units with Type=notify.

Why: with Type=exec, `systemctl start` and `restart` report success as soon as the
process runs, and a config error that ends it a second later shows only in the journal.
With Type=notify the start job waits for READY=1; a process that exits first fails the
job, so systemctl says so at once and `systemctl status` shows the error.

The protocol is one datagram on the unix socket named in $NOTIFY_SOCKET (a leading "@"
means the abstract namespace). Without that variable, outside systemd, this does nothing.
"""

from __future__ import annotations

import logging
import os
import socket

log = logging.getLogger(__name__)


def notify_ready() -> None:
    addr = os.environ.get("NOTIFY_SOCKET")
    if not addr:
        return
    if addr.startswith("@"):
        addr = "\0" + addr[1:]
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM) as s:
            s.connect(addr)
            s.sendall(b"READY=1")
    except OSError as e:
        # Not fatal: systemd then times the start out and says so.
        log.warning("could not tell systemd the service is ready: %s", e)
