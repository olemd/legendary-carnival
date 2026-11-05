#!/bin/sh
# Runs as root inside the systemd container started by e2e.sh, after the package has been
# installed. Each step prints a heading; the first failed check aborts the run.
# DEB is the path of the package file, used for the reinstall step.
set -eu

PY=/usr/lib/lanwatch/venv/bin/python
SOCK=/run/lanwatch/helper.sock

step() { printf '\n-- %s\n' "$*"; }
fail() {
    echo "FAIL: $*" >&2
    exit 1
}
main_pid() { systemctl show -p MainPID --value "$1"; }
# One field of /proc/<pid>/status, e.g. "CapEff".
proc_status() { awk -v k="$2:" '$1 == k { print $2 }' "/proc/$1/status"; }
as_service_user() { setpriv --reuid=lanwatch --regid=lanwatch --init-groups "$@"; }

step "socket and service are active after install"
systemctl is-active --quiet lanwatch-helper.socket || fail "lanwatch-helper.socket is not active"
i=0
until systemctl is-active --quiet lanwatch.service; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || fail "lanwatch.service did not become active"
    sleep 1
done
systemctl is-enabled --quiet lanwatch.service || fail "lanwatch.service is not enabled"

step "config file is readable by root and the lanwatch group only"
perms=$(stat -c '%U:%G %a' /etc/lanwatch/config.toml)
[ "$perms" = "root:lanwatch 640" ] || fail "config.toml is $perms"

step "web UI answers on loopback"
"$PY" - <<'PYEOF' || fail "no healthy answer from /api/health"
import json, time, urllib.request
for _ in range(60):
    try:
        with urllib.request.urlopen("http://127.0.0.1:8321/api/health", timeout=3) as r:
            print(json.load(r))
            raise SystemExit(0 if r.status == 200 else 1)
    except OSError:
        time.sleep(1)
raise SystemExit(1)
PYEOF

step "main service: user lanwatch, may bind low ports and nothing else, really sandboxed"
pid=$(main_pid lanwatch.service)
[ "$(stat -c %U "/proc/$pid")" = lanwatch ] || fail "main service runs as $(stat -c %U "/proc/$pid")"
# Bit 10 is CAP_NET_BIND_SERVICE, for the decoy ports. Nothing else, and no raw sockets.
[ "$(proc_status "$pid" CapEff)" = 0000000000000400 ] || fail "main service capabilities: $(proc_status "$pid" CapEff)"
[ "$(proc_status "$pid" CapBnd)" = 0000000000000400 ] || fail "main service bounding set: $(proc_status "$pid" CapBnd)"
[ "$(readlink "/proc/$pid/ns/mnt")" != "$(readlink /proc/1/ns/mnt)" ] ||
    fail "main service shares PID 1's mount namespace: the sandbox was not applied"
if journalctl -b --no-pager | grep -q "assuming containerized execution"; then
    fail "systemd skipped sandboxing (see journal)"
fi

step "the knock on decoy port 23 from another machine became a finding"
i=0
until lanwatch findings 2>/dev/null | grep -q "probed decoy port 23 (telnet)"; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || fail "no decoy finding: $(lanwatch findings 2>&1 | tail -5)"
    sleep 2
done
lanwatch findings | grep "probed decoy"

step "CLI as root works on the service's database, discovery uses arp-scan via the helper"
out=$(lanwatch scan --discovery-only 2>&1) || fail "scan failed: $out"
echo "$out"
echo "$out" | grep -q "via arp-scan" || fail "discovery did not use arp-scan"

step "helper: user lanwatch-helper, CAP_NET_RAW and nothing else"
hpid=$(main_pid lanwatch-helper.service)
[ "$hpid" -gt 0 ] || fail "helper is not running after a scan"
[ "$(stat -c %U "/proc/$hpid")" = lanwatch-helper ] || fail "helper runs as $(stat -c %U "/proc/$hpid")"
[ "$(proc_status "$hpid" CapAmb)" = 0000000000002000 ] || fail "helper ambient set is $(proc_status "$hpid" CapAmb)"
[ "$(proc_status "$hpid" CapBnd)" = 0000000000002000 ] || fail "helper bounding set is $(proc_status "$hpid" CapBnd)"
[ "$(readlink "/proc/$hpid/ns/mnt")" != "$(readlink /proc/1/ns/mnt)" ] ||
    fail "helper shares PID 1's mount namespace: the sandbox was not applied"

step "DHCP/mDNS broadcast probes are not skipped"
out=$(lanwatch infra 2>&1) || fail "infra failed: $out"
echo "$out"
if echo "$out" | grep -q "skipping DHCP/mDNS"; then
    fail "broadcast probes were skipped as unprivileged"
fi

step "UDP and version scans through the helper, as the service user"
gateway=$(ip -4 route show default | awk '{ print $3; exit }')
as_service_user "$PY" - "$SOCK" "$gateway" <<'PYEOF' || fail "scan through the helper failed"
import asyncio, sys
from pathlib import Path
from lanwatch.collectors.base import CommandError, HelperExecutor

async def main() -> None:
    ex = HelperExecutor(Path(sys.argv[1]))
    target = sys.argv[2]
    assert await ex.which("nmap") == (True, True), await ex.which("nmap")
    assert await ex.which("arp-scan") == (True, True), await ex.which("arp-scan")
    for flags in (["-sU", "--top-ports=5"], ["-sV", "--top-ports=20"]):
        rc, out, err = await ex.run(["nmap", "-oX", "-", "-n", "-Pn", *flags, target], 300)
        assert rc == 0 and "<nmaprun" in out and "<port " in out, (flags, rc, err[-400:])
        print("nmap", *flags, target, "-> ok")
    # The helper is the privilege boundary: nothing beyond this LAN, no other scripts.
    for argv in (["nmap", "-sn", "8.8.8.8"], ["nmap", "--script=vuln", target]):
        try:
            await ex.run(argv, 30)
        except CommandError as e:
            print(*argv, "-> refused:", str(e)[:70])
        else:
            raise AssertionError(f"helper ran {argv}")

asyncio.run(main())
PYEOF

step "nothing in the state directory is owned by anyone but lanwatch"
stray=$(find /var/lib/lanwatch ! -user lanwatch)
[ -z "$stray" ] || fail "not owned by lanwatch: $stray"
[ -f /var/lib/lanwatch/lanwatch.db ] || fail "no database in /var/lib/lanwatch"

step "other users are pointed to sudo"
if out=$(setpriv --reuid=nobody --regid=nogroup --clear-groups lanwatch version 2>&1); then
    fail "an unrelated user could run the system instance"
fi
echo "$out" | grep -q sudo || fail "unhelpful message: $out"

step "TLS from the bundled Python against the system CA store (httpx2 and stdlib ssl)"
"$PY" - <<'PYEOF' || fail "HTTPS request failed"
import urllib.request
import httpx2
httpx2.get("https://pypi.org/simple/pip/", timeout=30).raise_for_status()
urllib.request.urlopen("https://pypi.org/simple/pip/", timeout=30).close()
print("ok")
PYEOF

step "units pass systemd-analyze verify"
systemd-analyze verify --man=no /usr/lib/systemd/system/lanwatch.service \
    /usr/lib/systemd/system/lanwatch-helper.service /usr/lib/systemd/system/lanwatch-helper.socket ||
    fail "systemd-analyze verify"

step "exposure score (informational)"
systemd-analyze security --no-pager lanwatch.service lanwatch-helper.service | grep "Overall exposure" || true

step "a configuration error stops the service once, with the reason, instead of looping"
cp -p /etc/lanwatch/config.toml /etc/lanwatch/config.toml.good
printf '\n[web]\nhost = "0.0.0.0"\n' >>/etc/lanwatch/config.toml # reachable, but no password
systemctl restart lanwatch.service || true
i=0
until [ "$(systemctl is-failed lanwatch.service)" = failed ]; do
    i=$((i + 1))
    [ "$i" -lt 20 ] || fail "service did not end up failed: $(systemctl is-active lanwatch.service)"
    sleep 1
done
sleep 12 # longer than RestartSec: an automatic restart would have happened by now
[ "$(systemctl show -p NRestarts --value lanwatch.service)" = 0 ] || fail "systemd restarted it"
[ "$(systemctl is-failed lanwatch.service)" = failed ] || fail "service left the failed state"
journalctl -u lanwatch.service --no-pager -n 20 | grep -q "set web.password" ||
    fail "the journal does not say what is wrong"
mv /etc/lanwatch/config.toml.good /etc/lanwatch/config.toml
systemctl restart lanwatch.service
i=0
until systemctl is-active --quiet lanwatch.service; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || fail "service did not come back with the good config"
    sleep 1
done

step "reinstalling (the upgrade path) leaves everything running"
DEBIAN_FRONTEND=noninteractive apt-get install -y -q --reinstall "$DEB" >/dev/null
systemctl is-active --quiet lanwatch-helper.socket || fail "socket inactive after reinstall"
i=0
until systemctl is-active --quiet lanwatch.service; do
    i=$((i + 1))
    [ "$i" -lt 30 ] || fail "lanwatch.service inactive after reinstall"
    sleep 1
done
lanwatch devices >/dev/null || fail "CLI broken after reinstall"

step "purge removes configuration and state"
DEBIAN_FRONTEND=noninteractive apt-get purge -y -q lanwatch >/dev/null
[ ! -e /var/lib/lanwatch ] || fail "/var/lib/lanwatch survived purge"
[ ! -e /etc/lanwatch ] || fail "/etc/lanwatch survived purge"
if systemctl is-active --quiet lanwatch.service; then
    fail "lanwatch.service still active after purge"
fi

printf '\nall checks passed\n'
