#!/bin/sh
# End-to-end test of the Debian package: install dist/lanwatch_*_amd64.deb in a container
# that runs systemd as init, then run assert.sh inside it.
#
#   tests/deb/e2e.sh [IMAGE]            default image: docker.io/library/debian:13
#   PODMAN="sudo podman" tests/deb/e2e.sh ...
#
# The container is --privileged on purpose. Without CAP_SYS_ADMIN systemd cannot build the
# units' sandboxes, logs "assuming containerized execution" and starts them unsandboxed,
# and the test would pass without having tested the hardening. It gets its own network so
# the scans have a small, private subnet (the network's gateway) to look at.
set -eu

IMAGE=${1:-docker.io/library/debian:13}
PODMAN=${PODMAN:-podman}

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/../.." && pwd)

# This machine's architecture: the services run for real here, which emulation cannot do
# (see smoke.sh for other architectures).
arch=$(dpkg --print-architecture)
set -- "$root"/dist/lanwatch_*_"$arch".deb
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "expected exactly one dist/lanwatch_*_$arch.deb; run 'make deb' first" >&2
    exit 1
fi
deb=$(basename "$1")

name="lanwatch-e2e-$$"

# PODMAN may be "sudo podman", so it is split on purpose.
pm() {
    # shellcheck disable=SC2086
    $PODMAN "$@"
}

cleanup() {
    pm rm -f -t 0 "$name" >/dev/null 2>&1 || true
    pm network rm -f "$name" >/dev/null 2>&1 || true
}
trap cleanup EXIT
trap 'exit 130' INT TERM

echo "== $IMAGE: starting systemd container $name"
pm network create "$name" >/dev/null
# --arch is explicit because a local image tag can point at another architecture's variant
# (after `make deb-arm64` or smoke.sh); podman then fetches the right one.
pm run -d --name "$name" --arch "$arch" --privileged --systemd=always --network "$name" \
    -v "$root/dist:/dist:ro" -v "$here:/e2e:ro" "$IMAGE" \
    sh -c 'export DEBIAN_FRONTEND=noninteractive
           rm -f /usr/sbin/policy-rc.d
           apt-get update -q >/dev/null &&
           apt-get install -y -q systemd systemd-sysv dbus >/dev/null &&
           exec /sbin/init' >/dev/null

# The container first removes the image's policy-rc.d (it forbids starting services from
# package scripts, which no real machine does), installs systemd and execs it as PID 1.
# Wait for it to finish booting.
state=unknown
i=0
while [ "$i" -lt 120 ]; do
    state=$(pm exec "$name" systemctl is-system-running 2>/dev/null || true)
    case $state in running | degraded) break ;; esac
    if [ "$(pm inspect -f '{{.State.Running}}' "$name")" != true ]; then
        pm logs "$name" >&2 || true
        echo "container exited before systemd came up" >&2
        exit 1
    fi
    i=$((i + 1))
    sleep 2
done
case $state in
running | degraded) ;;
*)
    # Say what the container was doing: an empty state means systemd is not even installed
    # yet (apt still running or stuck), anything else that systemd itself is hanging.
    echo "systemd did not finish booting (state: ${state:-none, systemctl not available yet})" >&2
    echo "-- processes in the container:" >&2
    pm top "$name" >&2 || true
    echo "-- container log:" >&2
    pm logs --tail 40 "$name" >&2 || true
    exit 1
    ;;
esac

echo "== installing $deb"
pm exec -e DEBIAN_FRONTEND=noninteractive "$name" apt-get install -y -q "/dist/$deb" >/dev/null

if ! pm exec -e DEB="/dist/$deb" "$name" sh /e2e/assert.sh; then
    echo "== FAILED on $IMAGE; service logs:" >&2
    pm exec "$name" journalctl --no-pager -n 60 -u lanwatch -u lanwatch-helper >&2 || true
    exit 1
fi
echo "== OK on $IMAGE"
