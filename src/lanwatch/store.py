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

from lanwatch.collectors.services import PortObservation, PortSet
from lanwatch.models import (
    Device,
    EventRow,
    Finding,
    FindingRow,
    FindingStatus,
    HostObservation,
    InfraRow,
    Kind,
    NotificationRow,
    ServiceDiff,
    ServiceRow,
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
    # v2: service details, per-device scan bookkeeping, key/value meta
    """
    ALTER TABLE services ADD COLUMN extrainfo TEXT;
    ALTER TABLE services ADD COLUMN tunnel TEXT;
    ALTER TABLE services ADD COLUMN details TEXT NOT NULL DEFAULT '{}';
    CREATE TABLE device_scans (
        device_id         INTEGER PRIMARY KEY REFERENCES devices(id),
        last_inventory_at TEXT,
        last_deep_at      TEXT,
        inventory_count   INTEGER NOT NULL DEFAULT 0
    );
    CREATE TABLE meta (
        key   TEXT PRIMARY KEY,
        value TEXT NOT NULL
    );
    """,
    # v3: LLM device classification
    """
    ALTER TABLE devices ADD COLUMN description TEXT;
    ALTER TABLE devices ADD COLUMN kind_confidence REAL;
    """,
    # v4: notification log
    """
    CREATE TABLE notifications (
        id      INTEGER PRIMARY KEY,
        ts      TEXT NOT NULL,
        channel TEXT NOT NULL,
        kind    TEXT NOT NULL,
        title   TEXT NOT NULL,
        ok      INTEGER NOT NULL,
        error   TEXT
    );
    """,
    # v5: free-form device attributes (upnp, mdns, ipv6) and infra observations
    """
    ALTER TABLE devices ADD COLUMN attrs TEXT NOT NULL DEFAULT '{}';
    CREATE TABLE infra (
        kind        TEXT NOT NULL,
        key         TEXT NOT NULL,
        data        TEXT NOT NULL,
        first_seen  TEXT NOT NULL,
        last_seen   TEXT NOT NULL,
        snapshot_id INTEGER,
        PRIMARY KEY (kind, key)
    );
    """,
    # v6: event log for the timeline
    """
    CREATE TABLE events (
        id         INTEGER PRIMARY KEY,
        ts         TEXT NOT NULL,
        kind       TEXT NOT NULL,
        device_id  INTEGER REFERENCES devices(id),
        finding_id TEXT,
        summary    TEXT NOT NULL,
        data       TEXT NOT NULL DEFAULT '{}'
    );
    CREATE INDEX events_ts ON events(ts);
    CREATE INDEX events_device ON events(device_id, ts);
    """,
    # v7: manual classification, and several identities (MAC addresses) for one device
    """
    ALTER TABLE devices ADD COLUMN kind_manual INTEGER NOT NULL DEFAULT 0;
    CREATE TABLE device_aliases (
        key       TEXT PRIMARY KEY,
        device_id INTEGER NOT NULL REFERENCES devices(id)
    );
    """,
    # v8: accepting a finding for good, with the reason
    """
    ALTER TABLE findings ADD COLUMN accepted INTEGER NOT NULL DEFAULT 0;
    ALTER TABLE findings ADD COLUMN note TEXT;
    """,
    # v9: devices whose absence should raise a finding
    """
    ALTER TABLE devices ADD COLUMN watch INTEGER NOT NULL DEFAULT 0;
    """,
]


@dataclass(slots=True)
class RecordResult:
    seen_device_ids: list[int] = field(default_factory=list)
    new_device_ids: list[int] = field(default_factory=list)
    ip_changes: list[tuple[int, str, str]] = field(default_factory=list)  # device, old, new


class Store:
    def __init__(self, path: Path | str, check_same_thread: bool = True) -> None:
        if isinstance(path, Path):
            path.parent.mkdir(parents=True, exist_ok=True)
        self.path = str(path)
        self._db = sqlite3.connect(
            self.path, isolation_level=None, check_same_thread=check_same_thread, timeout=30
        )
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

    def prune(
        self,
        rounds_before: str | None = None,
        events_before: str | None = None,
        notifications_before: str | None = None,
    ) -> dict[str, int]:
        """Delete history older than the given ISO timestamps (None keeps everything of
        that sort). Returns rows deleted per table.

        The newest finished snapshot of every kind always stays, whatever its age: it is
        what "online now" and "last scan" are read from. Snapshots that current state
        still points to (a service's last scan, an infra record) stay as well."""
        deleted = {"sightings": 0, "snapshots": 0, "events": 0, "notifications": 0}
        newest = "SELECT MAX(id) FROM snapshots WHERE finished_at IS NOT NULL GROUP BY kind"
        with self._tx():
            if rounds_before is not None:
                old = f"SELECT id FROM snapshots WHERE started_at < ? AND id NOT IN ({newest})"
                deleted["sightings"] = self._db.execute(
                    f"DELETE FROM sightings WHERE snapshot_id IN ({old})", (rounds_before,)
                ).rowcount
                deleted["snapshots"] = self._db.execute(
                    f"""DELETE FROM snapshots WHERE started_at < ? AND id NOT IN ({newest})
                        AND id NOT IN (SELECT last_snapshot_id FROM services
                                       WHERE last_snapshot_id IS NOT NULL)
                        AND id NOT IN (SELECT snapshot_id FROM infra
                                       WHERE snapshot_id IS NOT NULL)
                        AND id NOT IN (SELECT snapshot_id FROM sightings)""",
                    (rounds_before,),
                ).rowcount
            if events_before is not None:
                deleted["events"] = self._db.execute(
                    "DELETE FROM events WHERE ts < ?", (events_before,)
                ).rowcount
            if notifications_before is not None:
                deleted["notifications"] = self._db.execute(
                    "DELETE FROM notifications WHERE ts < ?", (notifications_before,)
                ).rowcount
        return deleted

    def ip_holders(self) -> dict[str, list[tuple[int, str | None]]]:
        """Who answered for each IP in the newest finished discovery round:
        ip -> [(device id, MAC)]. More than one entry means two devices claimed the IP."""
        latest = self.latest_snapshot("discovery")
        if latest is None:
            return {}
        rows = self._db.execute(
            """SELECT s.ip, d.id, d.mac FROM sightings s JOIN devices d ON d.id = s.device_id
               WHERE s.snapshot_id = ? ORDER BY s.ip, d.id""",
            (latest.id,),
        ).fetchall()
        out: dict[str, list[tuple[int, str | None]]] = {}
        for r in rows:
            out.setdefault(str(r["ip"]), []).append((int(r["id"]), r["mac"]))
        return out

    def pin_infrastructure(self, ips: Iterable[str]) -> None:
        """Remember which MAC address holds each infrastructure IP (gateway, DHCP, DNS) the
        first time it is seen held by exactly one. A later change is then a finding."""
        holders = self.ip_holders()
        for ip in ips:
            macs = [mac for _, mac in holders.get(ip, []) if mac]
            if len(macs) == 1 and self.meta_get(f"net.pin.{ip}") is None:
                self.meta_set(f"net.pin.{ip}", macs[0])

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
        previous = self.latest_snapshot("discovery")
        prev_ids = self.sighting_device_ids(previous.id) if previous else set()
        with self._tx():
            for h in hosts:
                if h.key in seen_keys:
                    continue
                seen_keys.add(h.key)
                row = self._db.execute(
                    """SELECT * FROM devices WHERE key = ?1 OR id =
                       (SELECT device_id FROM device_aliases WHERE key = ?1)""",
                    (h.key,),
                ).fetchone()
                if row is not None and int(row["id"]) in result.seen_device_ids:
                    continue  # a second address of a merged device, already recorded this round
                if row is None:
                    cur = self._db.execute(
                        """INSERT INTO devices
                           (key, mac, ip, hostname, vendor, first_seen, last_seen)
                           VALUES (?, ?, ?, ?, ?, ?, ?)""",
                        (h.key, h.mac, h.ip, h.hostname, h.vendor, ts, ts),
                    )
                    device_id = int(cur.lastrowid or 0)
                    result.new_device_ids.append(device_id)
                    label = h.hostname or h.vendor or h.key
                    self.add_event(
                        "device.new",
                        f"New device {label} ({h.ip})",
                        device_id,
                        data={"ip": h.ip, "mac": h.mac, "vendor": h.vendor},
                    )
                else:
                    device_id = int(row["id"])
                    if row["ip"] and row["ip"] != h.ip:
                        result.ip_changes.append((device_id, str(row["ip"]), h.ip))
                        self.add_event(
                            "device.ip-changed",
                            f"{row['name'] or row['hostname'] or h.key}: {row['ip']} -> {h.ip}",
                            device_id,
                            data={"old": row["ip"], "new": h.ip},
                        )
                    if previous and device_id not in prev_ids:
                        self.add_event(
                            "presence.online",
                            f"{row['name'] or row['hostname'] or h.key} back online",
                            device_id,
                        )
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
            for gone in sorted(prev_ids - set(result.seen_device_ids)):
                d = self._db.execute(
                    "SELECT name, hostname, key FROM devices WHERE id = ?", (gone,)
                ).fetchone()
                if d is not None:
                    self.add_event(
                        "presence.offline",
                        f"{d['name'] or d['hostname'] or d['key']} went offline",
                        gone,
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

    def device_by_ip(self, ip: str) -> Device | None:
        """Most recently seen device with this IP (IPs move; identity is the MAC)."""
        if not ip:
            return None
        row = self._db.execute(
            "SELECT * FROM devices WHERE ip = ? ORDER BY last_seen DESC LIMIT 1", (ip,)
        ).fetchone()
        return _device(row, int(row["id"]) in self._online_ids()) if row else None

    def device_by_key(self, key: str) -> Device | None:
        row = self._db.execute("SELECT * FROM devices WHERE key = ?", (key,)).fetchone()
        return _device(row, int(row["id"]) in self._online_ids()) if row else None

    def set_device_name(self, device_id: int, name: str | None) -> bool:
        cur = self._db.execute("UPDATE devices SET name = ? WHERE id = ?", (name, device_id))
        if cur.rowcount > 0:
            self.add_event(
                "device.named", f"Named {name or '(cleared)'}", device_id, data={"name": name}
            )
            return True
        return False

    def set_device_kind(self, device_id: int, kind: str | None) -> bool:
        cur = self._db.execute("UPDATE devices SET kind = ? WHERE id = ?", (kind, device_id))
        return cur.rowcount > 0

    def edit_device(
        self,
        device_id: int,
        *,
        name: str | None,
        kind: str | None,
        description: str | None,
        watch: bool | None = None,
    ) -> bool:
        """Apply a person's edit of name, kind and description. False for an unknown device.

        Kind and description normally come from the LLM. Changing either here pins both:
        the classification will not overwrite them. Clearing both hands them back."""
        row = self._db.execute("SELECT * FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row is None:
            return False
        if name != row["name"]:
            self.set_device_name(device_id, name)
        if watch is not None:
            self.set_device_watch(device_id, watch)
        if (kind, description) != (row["kind"], row["description"]):
            manual = bool(kind or description)
            self._db.execute(
                """UPDATE devices SET kind = ?, description = ?, kind_manual = ?,
                   kind_confidence = NULL WHERE id = ?""",
                (kind, description, int(manual), device_id),
            )
            if kind != row["kind"]:
                self.add_event(
                    "device.classified",
                    f"Set to {kind}" if kind else "Classification cleared",
                    device_id,
                    data={"kind": kind, "previous": row["kind"], "by": "user"},
                )
        return True

    def set_device_watch(self, device_id: int, watch: bool) -> bool:
        cur = self._db.execute(
            "UPDATE devices SET watch = ? WHERE id = ? AND watch != ?",
            (int(watch), device_id, int(watch)),
        )
        if cur.rowcount > 0:
            self.add_event(
                "device.watch", "Watching for outages" if watch else "No longer watched", device_id
            )
        return cur.rowcount > 0

    def missed_rounds(self, device_id: int, look_back: int = 20) -> int:
        """How many of the most recent finished discovery rounds, counting back from the
        newest, the device did not answer in. 0 means it answered in the newest round."""
        rows = self._db.execute(
            """SELECT EXISTS(SELECT 1 FROM sightings
                             WHERE snapshot_id = s.id AND device_id = ?) AS seen
               FROM snapshots s WHERE s.kind = 'discovery' AND s.finished_at IS NOT NULL
               ORDER BY s.id DESC LIMIT ?""",
            (device_id, look_back),
        ).fetchall()
        missed = 0
        for r in rows:
            if r["seen"]:
                break
            missed += 1
        return missed

    def delete_device(self, device_id: int) -> bool:
        """Forget a device and everything recorded about it. Timeline events stay, without
        a link. If the device is still on the network, the next discovery adds it as new."""
        row = self._db.execute(
            "SELECT name, hostname, key FROM devices WHERE id = ?", (device_id,)
        ).fetchone()
        if row is None:
            return False
        with self._tx():
            for table in ("sightings", "services", "device_scans", "device_aliases", "findings"):
                self._db.execute(f"DELETE FROM {table} WHERE device_id = ?", (device_id,))
            self._db.execute("UPDATE events SET device_id = NULL WHERE device_id = ?", (device_id,))
            self._db.execute("DELETE FROM devices WHERE id = ?", (device_id,))
            self.add_event(
                "device.forgotten", f"Forgot {row['name'] or row['hostname'] or row['key']}"
            )
        return True

    def merge_devices(self, keep_id: int, other_id: int) -> bool:
        """Fold `other` into `keep`: the same physical device seen under two addresses,
        typically a phone that changed its private MAC. `other`'s address becomes an alias,
        so future sightings of it count as `keep`. Its history moves over; its services and
        findings are dropped, since the next scans produce them again under `keep`."""
        if keep_id == other_id:
            return False
        keep = self._db.execute("SELECT * FROM devices WHERE id = ?", (keep_id,)).fetchone()
        other = self._db.execute("SELECT * FROM devices WHERE id = ?", (other_id,)).fetchone()
        if keep is None or other is None:
            return False
        with self._tx():
            self._db.execute(
                "UPDATE device_aliases SET device_id = ? WHERE device_id = ?", (keep_id, other_id)
            )
            self._db.execute(
                "INSERT OR REPLACE INTO device_aliases(key, device_id) VALUES (?, ?)",
                (other["key"], keep_id),
            )
            self._db.execute(
                "UPDATE OR IGNORE sightings SET device_id = ? WHERE device_id = ?",
                (keep_id, other_id),
            )
            for table in ("sightings", "services", "device_scans", "findings"):
                self._db.execute(f"DELETE FROM {table} WHERE device_id = ?", (other_id,))
            self._db.execute(
                "UPDATE events SET device_id = ? WHERE device_id = ?", (keep_id, other_id)
            )
            # Keep the longer history and whatever `keep` did not know itself.
            self._db.execute(
                """UPDATE devices SET first_seen = MIN(first_seen, ?),
                   last_seen = MAX(last_seen, ?), hostname = COALESCE(hostname, ?),
                   vendor = COALESCE(vendor, ?), name = COALESCE(name, ?) WHERE id = ?""",
                (
                    other["first_seen"],
                    other["last_seen"],
                    other["hostname"],
                    other["vendor"],
                    other["name"],
                    keep_id,
                ),
            )
            self._db.execute("DELETE FROM devices WHERE id = ?", (other_id,))
            self.add_event(
                "device.merged",
                f"Merged {other['name'] or other['hostname'] or other['key']} into this device",
                keep_id,
                data={"alias": other["key"]},
            )
        return True

    def device_aliases(self, device_id: int) -> list[str]:
        rows = self._db.execute(
            "SELECT key FROM device_aliases WHERE device_id = ? ORDER BY key", (device_id,)
        ).fetchall()
        return [str(r[0]) for r in rows]

    def set_device_classification(
        self, device_id: int, kind: str, description: str, confidence: float
    ) -> bool:
        """Returns True when something actually changed."""
        before = self._db.execute("SELECT kind FROM devices WHERE id = ?", (device_id,)).fetchone()
        cur = self._db.execute(
            """UPDATE devices SET kind = ?, description = ?, kind_confidence = ?
               WHERE id = ? AND kind_manual = 0
                 AND (kind IS NOT ? OR description IS NOT ? OR kind_confidence IS NOT ?)""",
            (kind, description, confidence, device_id, kind, description, confidence),
        )
        changed = cur.rowcount > 0
        if changed and before is not None and before["kind"] != kind:
            self.add_event(
                "device.classified",
                f"Classified as {kind}: {description}",
                device_id,
                data={"kind": kind, "previous": before["kind"], "confidence": confidence},
            )
        return changed

    def _online_ids(self) -> set[int]:
        latest = self.latest_snapshot("discovery")
        return self.sighting_device_ids(latest.id) if latest else set()

    def devices_first_seen_since(self, since_iso: str) -> list[Device]:
        online = self._online_ids()
        rows = self._db.execute(
            "SELECT * FROM devices WHERE first_seen >= ? ORDER BY first_seen DESC", (since_iso,)
        ).fetchall()
        return [_device(r, int(r["id"]) in online) for r in rows]

    # -- services -----------------------------------------------------------

    def record_services(
        self,
        snapshot_id: int,
        device_id: int,
        ports: list[PortObservation],
        scanned: dict[str, PortSet],
        deep: bool = False,
    ) -> ServiceDiff:
        """Upsert open ports for a device; close ports that were scanned but not seen."""
        ts = iso(now_utc())
        with self._tx():
            prior = self._db.execute(
                "SELECT inventory_count FROM device_scans WHERE device_id = ?", (device_id,)
            ).fetchone()
            diff = ServiceDiff(device_id=device_id, first_scan=prior is None)
            seen: set[tuple[int, str]] = set()
            for p in ports:
                if p.state != "open":
                    continue
                seen.add((p.port, p.proto))
                row = self._db.execute(
                    "SELECT id, state FROM services WHERE device_id = ? AND port = ? AND proto = ?",
                    (device_id, p.port, p.proto),
                ).fetchone()
                details = json.dumps(p.scripts, sort_keys=True)
                if row is None:
                    self._db.execute(
                        """INSERT INTO services(device_id, port, proto, state, name, product,
                           version, extrainfo, tunnel, details, first_seen, last_seen,
                           last_snapshot_id)
                           VALUES (?, ?, ?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                        (
                            device_id,
                            p.port,
                            p.proto,
                            p.name,
                            p.product,
                            p.version,
                            p.extrainfo,
                            p.tunnel,
                            details,
                            ts,
                            ts,
                            snapshot_id,
                        ),
                    )
                    diff.opened.append((p.port, p.proto))
                    if prior is not None:
                        self.add_event(
                            "service.opened",
                            f"{p.port}/{p.proto} {p.name or ''} opened".rstrip(),
                            device_id,
                            data={"port": p.port, "proto": p.proto, "name": p.name},
                        )
                else:
                    if row["state"] != "open":
                        diff.opened.append((p.port, p.proto))
                        self.add_event(
                            "service.opened",
                            f"{p.port}/{p.proto} {p.name or ''} reopened".rstrip(),
                            device_id,
                            data={"port": p.port, "proto": p.proto, "name": p.name},
                        )
                    self._db.execute(
                        """UPDATE services SET state = 'open', name = COALESCE(?, name),
                           product = COALESCE(?, product), version = COALESCE(?, version),
                           extrainfo = COALESCE(?, extrainfo), tunnel = COALESCE(?, tunnel),
                           details = CASE WHEN ? = '{}' THEN details ELSE ? END,
                           last_seen = ?, last_snapshot_id = ? WHERE id = ?""",
                        (
                            p.name,
                            p.product,
                            p.version,
                            p.extrainfo,
                            p.tunnel,
                            details,
                            details,
                            ts,
                            snapshot_id,
                            row["id"],
                        ),
                    )
            open_rows = self._db.execute(
                "SELECT id, port, proto FROM services WHERE device_id = ? AND state = 'open'",
                (device_id,),
            ).fetchall()
            for r in open_rows:
                key = (int(r["port"]), str(r["proto"]))
                ps = scanned.get(key[1])
                if key not in seen and ps is not None and key[0] in ps:
                    self._db.execute(
                        "UPDATE services SET state = 'closed', last_snapshot_id = ? WHERE id = ?",
                        (snapshot_id, r["id"]),
                    )
                    diff.closed.append(key)
                    self.add_event(
                        "service.closed",
                        f"{key[0]}/{key[1]} closed",
                        device_id,
                        data={"port": key[0], "proto": key[1]},
                    )
            self._db.execute(
                """INSERT INTO device_scans
                   (device_id, last_inventory_at, last_deep_at, inventory_count)
                   VALUES (?, ?, ?, 1)
                   ON CONFLICT(device_id) DO UPDATE SET
                     last_inventory_at = excluded.last_inventory_at,
                     last_deep_at = COALESCE(excluded.last_deep_at, device_scans.last_deep_at),
                     inventory_count = device_scans.inventory_count + 1""",
                (device_id, ts, ts if deep else None),
            )
        return diff

    def services(self, device_id: int, open_only: bool = True) -> list[ServiceRow]:
        q = "SELECT * FROM services WHERE device_id = ?"
        if open_only:
            q += " AND state = 'open'"
        rows = self._db.execute(q + " ORDER BY proto, port", (device_id,)).fetchall()
        return [_service(r) for r in rows]

    def open_services(self) -> dict[int, list[ServiceRow]]:
        """All open services grouped by device id."""
        rows = self._db.execute(
            "SELECT * FROM services WHERE state = 'open' ORDER BY device_id, proto, port"
        ).fetchall()
        out: dict[int, list[ServiceRow]] = {}
        for r in rows:
            out.setdefault(int(r["device_id"]), []).append(_service(r))
        return out

    def last_inventory_at(self, device_id: int) -> str | None:
        row = self._db.execute(
            "SELECT last_inventory_at FROM device_scans WHERE device_id = ?", (device_id,)
        ).fetchone()
        return row[0] if row else None

    def devices_needing_deep_scan(self, older_than_iso: str) -> list[int]:
        rows = self._db.execute(
            """SELECT d.id FROM devices d LEFT JOIN device_scans s ON s.device_id = d.id
               WHERE s.last_deep_at IS NULL OR s.last_deep_at < ?""",
            (older_than_iso,),
        ).fetchall()
        return [int(r[0]) for r in rows]

    # -- events -------------------------------------------------------------

    def add_event(
        self,
        kind: str,
        summary: str,
        device_id: int | None = None,
        finding_id: str | None = None,
        data: dict[str, Any] | None = None,
    ) -> None:
        self._db.execute(
            "INSERT INTO events(ts, kind, device_id, finding_id, summary, data)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (iso(now_utc()), kind, device_id, finding_id, summary, json.dumps(data or {})),
        )

    def events(
        self,
        kinds: list[str] | None = None,
        device_id: int | None = None,
        since: str | None = None,
        limit: int = 200,
        exclude_prefix: str | None = None,
    ) -> list[EventRow]:
        q = "SELECT * FROM events WHERE 1=1"
        args: list[Any] = []
        if kinds:
            q += f" AND kind IN ({','.join('?' * len(kinds))})"
            args += kinds
        if device_id is not None:
            q += " AND device_id = ?"
            args.append(device_id)
        if since:
            q += " AND ts >= ?"
            args.append(since)
        if exclude_prefix:
            q += " AND kind NOT LIKE ?"
            args.append(exclude_prefix + "%")
        q += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        rows = self._db.execute(q, args).fetchall()
        return [
            EventRow(
                id=int(r["id"]),
                ts=str(r["ts"]),
                kind=str(r["kind"]),
                device_id=r["device_id"],
                finding_id=r["finding_id"],
                summary=str(r["summary"]),
                data=json.loads(r["data"]),
            )
            for r in rows
        ]

    def event_kinds(self) -> list[str]:
        rows = self._db.execute("SELECT DISTINCT kind FROM events ORDER BY kind").fetchall()
        return [str(r[0]) for r in rows]

    def snapshot_series(self, kind: str, since: str) -> list[tuple[str, int]]:
        """(finished_at, host_count) for finished snapshots of a kind since a timestamp."""
        rows = self._db.execute(
            "SELECT finished_at, host_count FROM snapshots"
            " WHERE kind = ? AND finished_at IS NOT NULL AND finished_at >= ? ORDER BY id",
            (kind, since),
        ).fetchall()
        return [(str(r[0]), int(r[1])) for r in rows]

    def search(self, q: str, limit: int = 50) -> dict[str, list[Any]]:
        """Substring search over devices, services and findings."""
        like = f"%{q.strip()}%"
        online = self._online_ids()
        devices = [
            _device(r, int(r["id"]) in online)
            for r in self._db.execute(
                """SELECT * FROM devices WHERE ip LIKE ? OR mac LIKE ? OR hostname LIKE ?
                   OR vendor LIKE ? OR name LIKE ? OR kind LIKE ? OR description LIKE ?
                   OR attrs LIKE ? ORDER BY last_seen DESC LIMIT ?""",
                (like,) * 8 + (limit,),
            ).fetchall()
        ]
        services = [
            _service(r)
            for r in self._db.execute(
                """SELECT * FROM services WHERE state = 'open' AND (CAST(port AS TEXT) = ?
                   OR name LIKE ? OR product LIKE ? OR version LIKE ? OR details LIKE ?)
                   ORDER BY device_id, port LIMIT ?""",
                (q.strip(), like, like, like, like, limit),
            ).fetchall()
        ]
        findings = [
            _finding(r)
            for r in self._db.execute(
                """SELECT * FROM findings WHERE title LIKE ? OR rule_id LIKE ? OR id LIKE ?
                   OR evidence LIKE ? ORDER BY last_seen DESC LIMIT ?""",
                (like, like, like, like, limit),
            ).fetchall()
        ]
        return {"devices": devices, "services": services, "findings": findings}

    # -- device attributes & infra ------------------------------------------

    def merge_device_attrs(self, device_id: int, attrs: dict[str, Any]) -> bool:
        row = self._db.execute("SELECT attrs FROM devices WHERE id = ?", (device_id,)).fetchone()
        if row is None:
            return False
        current = json.loads(row["attrs"] or "{}")
        merged = {**current, **attrs}
        if merged == current:
            return False
        self._db.execute(
            "UPDATE devices SET attrs = ? WHERE id = ?",
            (json.dumps(merged, sort_keys=True), device_id),
        )
        return True

    def replace_infra(
        self, kind: str, entries: dict[str, dict[str, Any]], snapshot_id: int
    ) -> None:
        """Current-state semantics: entries of this kind not in `entries` are removed."""
        ts = iso(now_utc())
        before = {r.key: r.data for r in self.infra(kind)}
        with self._tx():
            self._infra_events(kind, before, entries)
            for key, data in entries.items():
                self._db.execute(
                    """INSERT INTO infra(kind, key, data, first_seen, last_seen, snapshot_id)
                       VALUES (?, ?, ?, ?, ?, ?)
                       ON CONFLICT(kind, key) DO UPDATE SET data = excluded.data,
                         last_seen = excluded.last_seen, snapshot_id = excluded.snapshot_id""",
                    (kind, key, json.dumps(data, sort_keys=True), ts, ts, snapshot_id),
                )
            if entries:
                placeholders = ",".join("?" * len(entries))
                self._db.execute(
                    f"DELETE FROM infra WHERE kind = ? AND key NOT IN ({placeholders})",
                    (kind, *entries.keys()),
                )
            else:
                self._db.execute("DELETE FROM infra WHERE kind = ?", (kind,))

    def _infra_events(
        self, kind: str, before: dict[str, dict[str, Any]], after: dict[str, dict[str, Any]]
    ) -> None:
        if kind == "dhcp":
            for key in sorted(set(after) - set(before)):
                self.add_event(
                    "infra.dhcp-server",
                    f"DHCP server seen: {after[key].get('server')}",
                    data=after[key],
                )
            for key in sorted(set(before) - set(after)):
                self.add_event(
                    "infra.dhcp-server",
                    f"DHCP server gone: {before[key].get('server')}",
                    data=before[key],
                )
        elif kind == "upnp":

            def mappings(d: dict[str, Any]) -> dict[str, dict[str, Any]]:
                out: dict[str, dict[str, Any]] = {}
                for m in d.get("mappings", []):
                    mk = (
                        f"{m.get('external_port')}/{m.get('protocol')}->"
                        f"{m.get('internal_client')}:{m.get('internal_port')}"
                    )
                    out[mk] = m
                return out

            for key in set(before) | set(after):
                old, new = mappings(before.get(key, {})), mappings(after.get(key, {}))
                router = (after.get(key) or before.get(key) or {}).get("friendly_name") or key
                for mk in sorted(set(new) - set(old)):
                    self.add_event(
                        "infra.port-mapping", f"Port mapping added on {router}: {mk}", data=new[mk]
                    )
                for mk in sorted(set(old) - set(new)):
                    self.add_event(
                        "infra.port-mapping",
                        f"Port mapping removed on {router}: {mk}",
                        data=old[mk],
                    )

    def infra(self, kind: str) -> list[InfraRow]:
        rows = self._db.execute(
            "SELECT * FROM infra WHERE kind = ? ORDER BY key", (kind,)
        ).fetchall()
        return [
            InfraRow(
                kind=str(r["kind"]),
                key=str(r["key"]),
                data=json.loads(r["data"]),
                first_seen=str(r["first_seen"]),
                last_seen=str(r["last_seen"]),
            )
            for r in rows
        ]

    # -- notifications ------------------------------------------------------

    def record_notification(
        self, channel: str, kind: str, title: str, ok: bool, error: str | None
    ) -> None:
        self._db.execute(
            "INSERT INTO notifications(ts, channel, kind, title, ok, error)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (iso(now_utc()), channel, kind, title, int(ok), error),
        )

    def notifications(self, limit: int = 100) -> list[NotificationRow]:
        rows = self._db.execute(
            "SELECT * FROM notifications ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()
        return [
            NotificationRow(
                id=int(r["id"]),
                ts=str(r["ts"]),
                channel=str(r["channel"]),
                kind=str(r["kind"]),
                title=str(r["title"]),
                ok=bool(r["ok"]),
                error=r["error"],
            )
            for r in rows
        ]

    # -- meta ---------------------------------------------------------------

    def meta_get(self, key: str) -> str | None:
        row = self._db.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return str(row[0]) if row else None

    def meta_set(self, key: str, value: str) -> None:
        self._db.execute(
            "INSERT INTO meta(key, value) VALUES (?, ?)"
            " ON CONFLICT(key) DO UPDATE SET value = excluded.value",
            (key, value),
        )

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
                    "SELECT status, accepted FROM findings WHERE id = ?", (f.id,)
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
                    self.add_event(
                        "finding.opened",
                        f"[{f.severity.value}] {f.title}",
                        f.device_id,
                        f.id,
                        data={"rule_id": f.rule_id, "severity": f.severity.value},
                    )
                else:
                    # A resolved finding that reappears is open again. Acked stays acked,
                    # and an accepted one comes back acknowledged without a fuss.
                    status = row["status"]
                    new_status = status
                    if status == "resolved":
                        new_status = "acked" if row["accepted"] else "open"
                    if status == "resolved" and not row["accepted"]:
                        self.add_event(
                            "finding.reopened",
                            f"[{f.severity.value}] {f.title}",
                            f.device_id,
                            f.id,
                            data={"rule_id": f.rule_id, "severity": f.severity.value},
                        )
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
                    r = self._db.execute(
                        "SELECT title, device_id, rule_id FROM findings WHERE id = ?", (fid,)
                    ).fetchone()
                    if r is not None:
                        self.add_event(
                            "finding.resolved",
                            f"Resolved: {r['title']}",
                            r["device_id"],
                            fid,
                            data={"rule_id": r["rule_id"]},
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

    def ack(self, finding_id: str, accept: bool = False, note: str | None = None) -> bool:
        """Acknowledge an open finding: seen, stop reporting it as new.

        With `accept`, also mark it as intended, with the reason in `note`. An accepted
        finding stays acknowledged even if it resolves and later reappears. Accepting works
        on an already acknowledged finding too."""
        if accept:
            cur = self._db.execute(
                """UPDATE findings SET status = 'acked', accepted = 1, note = ?
                   WHERE id = ? AND status IN ('open', 'acked')""",
                (note, finding_id),
            )
        else:
            cur = self._db.execute(
                "UPDATE findings SET status = 'acked' WHERE id = ? AND status = 'open'",
                (finding_id,),
            )
        if cur.rowcount > 0:
            r = self._db.execute(
                "SELECT title, device_id FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            if accept:
                summary = f"Accepted: {r['title']}" + (f" ({note})" if note else "")
                self.add_event(
                    "finding.accepted", summary, r["device_id"], finding_id, data={"note": note}
                )
            else:
                self.add_event(
                    "finding.acked", f"Acknowledged: {r['title']}", r["device_id"], finding_id
                )
            return True
        return False

    def reopen(self, finding_id: str) -> bool:
        """Undo an acknowledgement or acceptance: the finding is open again."""
        cur = self._db.execute(
            """UPDATE findings SET status = 'open', accepted = 0, note = NULL
               WHERE id = ? AND status = 'acked'""",
            (finding_id,),
        )
        if cur.rowcount > 0:
            r = self._db.execute(
                "SELECT title, device_id FROM findings WHERE id = ?", (finding_id,)
            ).fetchone()
            self.add_event(
                "finding.reopened",
                f"Reopened: {r['title']}",
                r["device_id"],
                finding_id,
                data={"by": "user"},
            )
            return True
        return False

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
        description=row["description"],
        kind_confidence=row["kind_confidence"],
        first_seen=str(row["first_seen"]),
        last_seen=str(row["last_seen"]),
        online=online,
        attrs=json.loads(row["attrs"] or "{}"),
        kind_manual=bool(row["kind_manual"]),
        watch=bool(row["watch"]),
    )


def _service(row: sqlite3.Row) -> ServiceRow:
    return ServiceRow(
        id=int(row["id"]),
        device_id=int(row["device_id"]),
        port=int(row["port"]),
        proto=str(row["proto"]),
        state=str(row["state"]),
        name=row["name"],
        product=row["product"],
        version=row["version"],
        extrainfo=row["extrainfo"],
        tunnel=row["tunnel"],
        details=json.loads(row["details"] or "{}"),
        first_seen=str(row["first_seen"]),
        last_seen=str(row["last_seen"]),
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
        accepted=bool(row["accepted"]),
        note=row["note"],
    )
