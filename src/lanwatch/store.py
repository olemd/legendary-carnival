"""SQLite store. Snapshots are append-only; devices and findings are upserted.

Device identity: MAC when known, otherwise "ip:<addr>". A device seen first by IP and
later with a MAC is two devices; merging is a manual operation (future `devices merge`).
"""

from __future__ import annotations

import json
import sqlite3
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from lanwatch.models import (
    Device,
    Finding,
    FindingRow,
    FindingStatus,
    HostObservation,
    Kind,
    Severity,
    Snapshot,
    iso,
    now_utc,
)

MIGRATIONS: list[str] = [
    # v1
    """
    CREATE TABLE devices (
        id          INTEGER PRIMARY KEY,
        key         TEXT NOT NULL UNIQUE,
        mac         TEXT,
        ip          TEXT,
        hostname    TEXT,
        vendor      TEXT,
        name        TEXT,
        kind        TEXT,
        notes       TEXT,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL
    );
    CREATE TABLE snapshots (
        id          INTEGER PRIMARY KEY,
        kind        TEXT NOT NULL,
        source      TEXT NOT NULL,
        started_at  TEXT NOT NULL,
        finished_at TEXT,
        host_count  INTEGER NOT NULL DEFAULT 0
    );
    CREATE INDEX snapshots_kind_finished ON snapshots(kind, finished_at);
    CREATE TABLE sightings (
        snapshot_id INTEGER NOT NULL REFERENCES snapshots(id),
        device_id   INTEGER NOT NULL REFERENCES devices(id),
        ip          TEXT NOT NULL,
        hostname    TEXT,
        PRIMARY KEY (snapshot_id, device_id)
    );
    CREATE TABLE services (
        id               INTEGER PRIMARY KEY,
        device_id        INTEGER NOT NULL REFERENCES devices(id),
        port             INTEGER NOT NULL,
        proto            TEXT NOT NULL,
        state            TEXT NOT NULL,
        name             TEXT,
        product          TEXT,
        version          TEXT,
        first_seen       TEXT NOT NULL,
        last_seen        TEXT NOT NULL,
        last_snapshot_id INTEGER REFERENCES snapshots(id),
        UNIQUE (device_id, port, proto)
    );
    CREATE TABLE findings (
        id          TEXT PRIMARY KEY,
        rule_id     TEXT NOT NULL,
        severity    TEXT NOT NULL,
        kind        TEXT NOT NULL,
        title       TEXT NOT NULL,
        device_id   INTEGER REFERENCES devices(id),
        evidence    TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        status      TEXT NOT NULL DEFAULT 'open',
        explanation TEXT
    );
    CREATE INDEX findings_status ON findings(status);
    CREATE TABLE llm_cache (
        key        TEXT PRIMARY KEY,
        model      TEXT NOT NULL,
        created_at TEXT NOT NULL,
        response   TEXT NOT NULL
    );
    """,
]


@dataclass(slots=True)
class RecordResult:
    seen_device_ids: list[int] = field(default_factory=list)
    new_device_ids: list[int] = field(default_factory=list)
    ip_changes: list[tuple[int, str, str]] = field(default_factory=list)  # device, old, new


class Store:
    def __init__(self, path: Path | str) -> None:
        if isinstance(path, Path):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        self._db = sqlite3.connect(self.path, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        if self.path != ":memory:":
            self._db.execute("PRAGMA journal_mode = WAL")
        self.migrate()

    @classmethod
    def memory(cls) -> Store:
        return cls(":memory:")

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> Store:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- schema -------------------------------------------------------------

    @property
    def schema_version(self) -> int:
        row = self._db.execute("PRAGMA user_version").fetchone()
        return int(row[0])

    def migrate(self) -> None:
        current = self.schema_version
        for version, sql in enumerate(MIGRATIONS, start=1):
            if version <= current:
                continue
            # executescript() commits any pending transaction first, so the
            # transaction must live inside the script itself.
            self._db.executescript(f"BEGIN;\n{sql}\nPRAGMA user_version = {version};\nCOMMIT;")

    def _tx(self) -> _Tx:
        return _Tx(self._db)

    # -- snapshots ----------------------------------------------------------

    def begin_snapshot(self, kind: str, source: str) -> int:
        cur = self._db.execute(
            "INSERT INTO snapshots(kind, source, started_at) VALUES (?, ?, ?)",
            (kind, source, iso(now_utc())),
        )
        return int(cur.lastrowid or 0)

    def finish_snapshot(self, snapshot_id: int, host_count: int) -> None:
        self._db.execute(
            "UPDATE snapshots SET finished_at = ?, host_count = ? WHERE id = ?",
            (iso(now_utc()), host_count, snapshot_id),
        )

    def snapshot(self, snapshot_id: int) -> Snapshot | None:
        row = self._db.execute("SELECT * FROM snapshots WHERE id = ?", (snapshot_id,)).fetchone()
        return _snapshot(row) if row else None

    def latest_snapshot(self, kind: str, before_id: int | None = None) -> Snapshot | None:
        q = "SELECT * FROM snapshots WHERE kind = ? AND finished_at IS NOT NULL"
        args: list[Any] = [kind]
        if before_id is not None:
            q += " AND id < ?"
            args.append(before_id)
        row = self._db.execute(q + " ORDER BY id DESC LIMIT 1", args).fetchone()
        return _snapshot(row) if row else None

    def finished_snapshot_count(self, kind: str) -> int:
        row = self._db.execute(
            "SELECT COUNT(*) FROM snapshots WHERE kind = ? AND finished_at IS NOT NULL", (kind,)
        ).fetchone()
        return int(row[0])

    def sighting_device_ids(self, snapshot_id: int) -> set[int]:
        rows = self._db.execute(
            "SELECT device_id FROM sightings WHERE snapshot_id = ?", (snapshot_id,)
        ).fetchall()
        return {int(r[0]) for r in rows}

    # -- devices ------------------------------------------------------------

    def record_hosts(self, snapshot_id: int, hosts: Iterable[HostObservation]) -> RecordResult:
        """Upsert devices from one discovery round and record sightings."""
        result = RecordResult()
        ts = iso(now_utc())
        seen_keys: set[str] = set()
        with self._tx():
            for h in hosts:
                if h.key in seen_keys:
                    continue
                seen_keys.add(h.key)
                row = self._db.execute("SELECT * FROM devices WHERE key = ?", (h.key,)).fetchone()
                if row is None:
                    cur = self._db.execute(
                        """INSERT INTO devices
                           (key, mac, ip, hostname, vendor, first_seen, last_seen)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (h.key, h.mac, h.ip, h.hostname, h.vendor, ts, ts),
                    )
                    device_id = int(cur.lastrowid or 0)
                    result.new_device_ids.append(device_id)
                else:
                    device_id = int(row["id"])
                    if row["ip"] and row["ip"] != h.ip:
                        result.ip_changes.append((device_id, str(row["ip"]), h.ip))
                    self._db.execute(
                        """UPDATE devices SET ip = ?, hostname = COALESCE(?, hostname),
                           vendor = COALESCE(?, vendor), last_seen = ? WHERE id = ?""",
                        (h.ip, h.hostname, h.vendor, ts, device_id),
                    )
                result.seen_device_ids.append(device_id)
                self._db.execute(
                    "INSERT OR REPLACE INTO sightings(snapshot_id, device_id, ip, hostname)"
                    " VALUES (?, ?, ?, ?)",
                    (snapshot_id, device_id, h.ip, h.hostname),
                )
        return result

    def devices(self, online_only: bool = False) -> list[Device]:
        online = self._online_ids()
        rows = self._db.execute("SELECT * FROM devices ORDER BY last_seen DESC, ip").fetchall()
        out = [_device(r, int(r["id"]) in online) for r in rows]
        return [d for d in out if d.online] if online_only else out

    def device(self, device_id: int) -> Device | None:
        row = self._db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        return _device(row, int(row["id"]) in self._online_ids()) if row else None

    def device_by_key(self, key: str) -> Device | None:
        row = self._db.execute("SELECT * FROM devices WHERE key = ?", (key,)).fetchone()
        return _device(row, int(row["id"]) in self._online_ids()) if row else None

    def set_device_name(self, device_id: int, name: str | None) -> bool:
        cur = self._db.execute("UPDATE devices SET name = ? WHERE id = ?", (name, device_id))
        return cur.rowcount > 0

    def set_device_kind(self, device_id: int, kind: str | None) -> bool:
        cur = self._db.execute("UPDATE devices SET kind = ? WHERE id = ?", (kind, device_id))
        return cur.rowcount > 0

    def _online_ids(self) -> set[int]:
        latest = self.latest_snapshot("discovery")
        return self.sighting_device_ids(latest.id) if latest else set()

    def devices_first_seen_since(self, since_iso: str) -> list[Device]:
        online = self._online_ids()
        rows = self._db.execute(
            "SELECT * FROM devices WHERE first_seen >= ? ORDER BY first_seen DESC", (since_iso,)
        ).fetchall()
        return [_device(r, int(r["id"]) in online) for r in rows]

    # -- findings -----------------------------------------------------------

    def upsert_findings(
        self,
        findings: Iterable[Finding],
        ran_rules: set[str],
        auto_resolve_rules: set[str],
    ) -> tuple[list[str], list[str]]:
        """Insert/update findings; auto-resolve stale ones for rules that ran.

        Returns (new_ids, resolved_ids).
        """
        ts = iso(now_utc())
        new_ids: list[str] = []
        emitted: set[str] = set()
        with self._tx():
            for f in findings:
                emitted.add(f.id)
                row = self._db.execute(
                    "SELECT status FROM findings WHERE id = ?", (f.id,)
                ).fetchone()
                if row is None:
                    self._db.execute(
                        """INSERT INTO findings(id, rule_id, severity, kind, title, device_id,
                           evidence, first_seen, last_seen, status)
                           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'open')""",
                        (
                            f.id,
                            f.rule_id,
                            f.severity.value,
                            f.kind.value,
                            f.title,
                            f.device_id,
                            json.dumps(f.evidence, sort_keys=True),
                            ts,
                            ts,
                        ),
                    )
                    new_ids.append(f.id)
                else:
                    # A resolved finding that reappears is open again. Acked stays acked.
                    status = row["status"]
                    new_status = "open" if status == "resolved" else status
                    self._db.execute(
                        """UPDATE findings SET severity = ?, title = ?, evidence = ?,
                           last_seen = ?, status = ? WHERE id = ?""",
                        (
                            f.severity.value,
                            f.title,
                            json.dumps(f.evidence, sort_keys=True),
                            ts,
                            new_status,
                            f.id,
                        ),
                    )
            resolved_ids: list[str] = []
            rules = sorted(ran_rules & auto_resolve_rules)
            if rules:
                placeholders = ",".join("?" * len(rules))
                rows = self._db.execute(
                    "SELECT id FROM findings WHERE status != 'resolved'"
                    f" AND rule_id IN ({placeholders})",
                    rules,
                ).fetchall()
                resolved_ids = [str(r["id"]) for r in rows if str(r["id"]) not in emitted]
                for fid in resolved_ids:
                    self._db.execute(
                        "UPDATE findings SET status = 'resolved', last_seen = ? WHERE id = ?",
                        (ts, fid),
                    )
        return new_ids, resolved_ids

    def findings(self, status: FindingStatus | None = FindingStatus.OPEN) -> list[FindingRow]:
        q = "SELECT * FROM findings"
        args: list[Any] = []
        if status is not None:
            q += " WHERE status = ?"
            args.append(status.value)
        rows = self._db.execute(q + " ORDER BY last_seen DESC", args).fetchall()
        out = [_finding(r) for r in rows]
        out.sort(key=lambda f: (f.severity.rank, f.last_seen))
        return out

    def finding(self, finding_id: str) -> FindingRow | None:
        row = self._db.execute("SELECT * FROM findings WHERE id = ?", (finding_id,)).fetchone()
        return _finding(row) if row else None

    def ack(self, finding_id: str) -> bool:
        cur = self._db.execute(
            "UPDATE findings SET status = 'acked' WHERE id = ? AND status = 'open'", (finding_id,)
        )
        return cur.rowcount > 0

    def set_explanation(self, finding_id: str, text: str) -> None:
        self._db.execute("UPDATE findings SET explanation = ? WHERE id = ?", (text, finding_id))

    # -- llm cache ----------------------------------------------------------

    def llm_cache_get(self, key: str) -> str | None:
        row = self._db.execute("SELECT response FROM llm_cache WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row else None

    def llm_cache_put(self, key: str, model: str, response: str) -> None:
        self._db.execute(
            "INSERT OR REPLACE INTO llm_cache(key, model, created_at, response)"
            " VALUES (?, ?, ?, ?)",
            (key, model, iso(now_utc()), response),
        )


class _Tx:
    def __init__(self, db: sqlite3.Connection) -> None:
        self._db = db

    def __enter__(self) -> None:
        self._db.execute("BEGIN")

    def __exit__(self, exc_type: object, *_: object) -> None:
        self._db.execute("ROLLBACK" if exc_type else "COMMIT")


def _snapshot(row: sqlite3.Row) -> Snapshot:
    return Snapshot(
        id=int(row["id"]),
        kind=str(row["kind"]),
        source=str(row["source"]),
        started_at=str(row["started_at"]),
        finished_at=row["finished_at"],
        host_count=int(row["host_count"]),
    )


def _device(row: sqlite3.Row, online: bool) -> Device:
    return Device(
        id=int(row["id"]),
        key=str(row["key"]),
        mac=row["mac"],
        ip=row["ip"],
        hostname=row["hostname"],
        vendor=row["vendor"],
        name=row["name"],
        kind=row["kind"],
        first_seen=str(row["first_seen"]),
        last_seen=str(row["last_seen"]),
        online=online,
    )


def _finding(row: sqlite3.Row) -> FindingRow:
    return FindingRow(
        id=str(row["id"]),
        rule_id=str(row["rule_id"]),
        severity=Severity(row["severity"]),
        kind=Kind(row["kind"]),
        title=str(row["title"]),
        device_id=row["device_id"],
        evidence=json.loads(row["evidence"]),
        first_seen=str(row["first_seen"]),
        last_seen=str(row["last_seen"]),
        status=FindingStatus(row["status"]),
        explanation=row["explanation"],
    )
