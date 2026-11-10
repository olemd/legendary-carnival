"""Service rules. They read the current open-services state from the store, so a finding
lives exactly as long as the condition does, regardless of which devices a round scanned.

These are audit checks for a network you administer: they flag configurations that are
widely considered unsafe on a shared segment, so you can decide what to do about them.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Any

from lanwatch.models import Device, Finding, Kind, ServiceRow, Severity
from lanwatch.rules.base import Rule, RuleContext
from lanwatch.rules.snmp_audit import AUDIT_RULES


def _device_services(ctx: RuleContext) -> list[tuple[Device, list[ServiceRow]]]:
    out: list[tuple[Device, list[ServiceRow]]] = []
    for device_id, services in ctx.store.open_services().items():
        d = ctx.store.device(device_id)
        if d is not None:
            out.append((d, services))
    return out


def _svc_evidence(s: ServiceRow) -> dict[str, Any]:
    return {
        "port": s.port,
        "proto": s.proto,
        "service": s.name,
        "product": s.product,
        "version": s.version,
        "last_seen": s.last_seen,
    }


class ServiceRule(Rule):
    """Base for rules that look at one open service at a time."""

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        """Return (title, extra evidence) when the service matches."""
        raise NotImplementedError

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for device, services in _device_services(ctx):
            for s in services:
                hit = self.check(device, s)
                if hit is None:
                    continue
                title, extra = hit
                out.append(
                    self.finding(
                        ctx,
                        title=f"{title}: {device.label} ({device.ip})",
                        key_parts=[device.key, str(s.port), s.proto],
                        device_id=device.id,
                        evidence={**_svc_evidence(s), **extra},
                    )
                )
        return out


CLEARTEXT_REMOTE = {23: "telnet", 512: "rexec", 513: "rlogin", 514: "rsh"}


class CleartextRemoteAccessRule(ServiceRule):
    id = "service.cleartext-remote-access"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = "Unencrypted remote login service (telnet, rsh family) is reachable."

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        if s.proto != "tcp":
            return None
        name = CLEARTEXT_REMOTE.get(s.port) or (
            s.name if s.name in CLEARTEXT_REMOTE.values() else None
        )
        if name is None:
            return None
        return f"Cleartext remote access ({name})", {"protocol": name}


class FtpCleartextRule(ServiceRule):
    id = "service.ftp-cleartext"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    description = "FTP without TLS. Credentials and files cross the network unencrypted."

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        if s.proto == "tcp" and (s.port == 21 or s.name == "ftp") and s.tunnel != "ssl":
            return "FTP without TLS", {}
        return None


class Smb1Rule(ServiceRule):
    id = "service.smb1-enabled"
    kind = Kind.SECURITY
    default_severity = Severity.HIGH
    description = "SMBv1 dialect accepted. Deprecated protocol with known weaknesses."

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        data = s.script("smb-protocols")
        if not isinstance(data, dict):
            return None
        dialects = data.get("dialects")
        if not isinstance(dialects, list):
            return None
        if any("NT LM 0.12" in str(d) or "SMBv1" in str(d) for d in dialects):
            return "SMBv1 enabled", {"dialects": [str(d) for d in dialects]}
        return None


class VncNoAuthRule(ServiceRule):
    id = "service.vnc-no-auth"
    kind = Kind.SECURITY
    default_severity = Severity.CRITICAL
    description = "VNC server accepts connections without authentication."

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        raw = s.details.get("vnc-info")
        output = str(raw.get("output", "")) if isinstance(raw, dict) else ""
        if "Security types:" in output and "None" in output.split("Security types:", 1)[1]:
            return "VNC without authentication", {"vnc_info": output.strip()[:300]}
        return None


DATABASES = {
    3306: "mysql",
    5432: "postgresql",
    6379: "redis",
    27017: "mongodb",
    9200: "elasticsearch",
    1433: "ms-sql",
    11211: "memcached",
    5984: "couchdb",
}


class DatabaseExposedRule(ServiceRule):
    id = "service.database-exposed"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    description = (
        "Database service reachable from the whole segment. Usually only one client needs it."
    )

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        if s.proto != "tcp":
            return None
        name = DATABASES.get(s.port)
        if name is None:
            return None
        return f"Database exposed ({name})", {"database": name}


WEAK_KEX = {"diffie-hellman-group1-sha1", "diffie-hellman-group-exchange-sha1"}
WEAK_CIPHER_PREFIXES = ("arcfour", "3des-cbc", "blowfish-cbc", "cast128-cbc", "des-cbc")
WEAK_MAC = {"hmac-md5", "hmac-md5-96", "hmac-sha1-96", "umac-64@openssh.com"}


class SshWeakAlgorithmsRule(ServiceRule):
    id = "ssh.weak-algorithms"
    kind = Kind.SECURITY
    default_severity = Severity.MEDIUM
    description = "SSH server offers legacy key exchange, cipher or MAC algorithms."

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        data = s.script("ssh2-enum-algos")
        if not isinstance(data, dict):
            return None
        weak: dict[str, list[str]] = {}
        kex = [str(a) for a in data.get("kex_algorithms", []) if str(a) in WEAK_KEX]
        ciphers = [
            str(a)
            for a in data.get("encryption_algorithms", [])
            if str(a).startswith(WEAK_CIPHER_PREFIXES)
        ]
        macs = [str(a) for a in data.get("mac_algorithms", []) if str(a) in WEAK_MAC]
        if kex:
            weak["kex"] = kex
        if ciphers:
            weak["ciphers"] = ciphers
        if macs:
            weak["macs"] = macs
        if not weak:
            return None
        return "SSH legacy algorithms", {"weak": weak}


def _parse_nmap_date(s: str) -> datetime | None:
    try:
        return datetime.fromisoformat(s).replace(tzinfo=UTC)
    except ValueError:
        return None


class TlsCertificateRule(ServiceRule):
    id = "tls.certificate"
    kind = Kind.PROBLEM
    default_severity = Severity.LOW
    description = "TLS certificate is expired or expires within 14 days."

    def check(self, device: Device, s: ServiceRow) -> tuple[str, dict[str, Any]] | None:
        data = s.script("ssl-cert")
        if not isinstance(data, dict):
            return None
        validity = data.get("validity")
        if not isinstance(validity, dict):
            return None
        not_after = _parse_nmap_date(str(validity.get("notAfter", "")))
        if not_after is None:
            return None
        now = datetime.now(UTC)
        subject = data.get("subject")
        cn = subject.get("commonName") if isinstance(subject, dict) else None
        ev = {"not_after": not_after.isoformat(), "common_name": cn}
        if not_after < now:
            return "TLS certificate expired", ev
        if not_after < now + timedelta(days=14):
            return "TLS certificate expiring soon", ev
        return None


class ServiceChangedRule(Rule):
    id = "inventory.service-changed"
    kind = Kind.SECURITY
    default_severity = Severity.LOW
    auto_resolve = False
    description = "A known device started listening on a port it did not before."

    def evaluate(self, ctx: RuleContext) -> list[Finding]:
        out: list[Finding] = []
        for device_id, diff in ctx.service_diffs.items():
            if diff.first_scan or not diff.opened:
                continue
            d = ctx.store.device(device_id)
            if d is None:
                continue
            ports = ", ".join(f"{p}/{proto}" for p, proto in sorted(diff.opened))
            out.append(
                self.finding(
                    ctx,
                    title=f"New open ports on {d.label} ({d.ip}): {ports}",
                    key_parts=[d.key, ports],
                    device_id=d.id,
                    evidence={
                        "opened": [f"{p}/{proto}" for p, proto in sorted(diff.opened)],
                        "closed": [f"{p}/{proto}" for p, proto in sorted(diff.closed)],
                    },
                )
            )
        return out


RULES: list[Rule] = [
    CleartextRemoteAccessRule(),
    FtpCleartextRule(),
    Smb1Rule(),
    VncNoAuthRule(),
    DatabaseExposedRule(),
    SshWeakAlgorithmsRule(),
    TlsCertificateRule(),
    ServiceChangedRule(),
    *AUDIT_RULES,
]
