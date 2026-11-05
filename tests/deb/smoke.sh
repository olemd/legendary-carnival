#!/bin/sh
# Smoke test of the Debian package for a CPU architecture other than this machine's, run
# under emulation:
#
#   tests/deb/smoke.sh arm64 [IMAGE]        default image: docker.io/library/debian:13
#
# It installs the package and checks that the bundled Python and its compiled libraries
# start and that TLS verification works. It deliberately does not start the services:
# under user-mode emulation systemd's system-call filters see the emulator's system calls,
# not the service's, so the sandboxed units cannot run there. The full test (e2e.sh) needs
# real hardware of that architecture.
set -eu

ARCH=${1:?usage: smoke.sh ARCH [IMAGE]}
IMAGE=${2:-docker.io/library/debian:13}
PODMAN=${PODMAN:-podman}

here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root=$(CDPATH='' cd -- "$here/../.." && pwd)

set -- "$root"/dist/lanwatch_*_"$ARCH".deb
if [ "$#" -ne 1 ] || [ ! -f "$1" ]; then
    echo "expected exactly one dist/lanwatch_*_$ARCH.deb; run 'make deb-$ARCH' first" >&2
    exit 1
fi
deb=$(basename "$1")

# Running another architecture's variant of IMAGE moves the local tag to it, and every
# later use of that tag on this machine would get it. Put the tag back when done.
restore() {
    # shellcheck disable=SC2086
    $PODMAN pull -q --arch "$(dpkg --print-architecture)" "$IMAGE" >/dev/null 2>&1 || true
}
trap restore EXIT

echo "== $IMAGE ($ARCH): installing $deb"
# PODMAN may be "sudo podman", so it is split on purpose. The quoted script is meant for the
# shell inside the container, so its variables must not expand here.
# shellcheck disable=SC2086,SC2016
$PODMAN run --rm --arch "$ARCH" -e DEB="/dist/$deb" -v "$root/dist:/dist:ro" "$IMAGE" sh -ec '
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -q >/dev/null
    apt-get install -y -q "$DEB" >/dev/null
    echo "-- architecture: $(dpkg --print-architecture), $(uname -m)"
    echo "-- CLI through the wrapper (drops from root to the lanwatch user)"
    lanwatch version
    lanwatch config path
    echo "-- compiled libraries and TLS against the system CA store"
    /usr/lib/lanwatch/venv/bin/python - <<PYEOF
import platform, urllib.request
import httptools, pydantic_core, uvloop, watchfiles, websockets, yaml
import httpx2
import lanwatch.cli, lanwatch.helper, lanwatch.web.app
print(platform.machine(), platform.python_version())
httpx2.get("https://pypi.org/simple/pip/", timeout=60).raise_for_status()
urllib.request.urlopen("https://pypi.org/simple/pip/", timeout=60).close()
print("ok")
PYEOF
    echo "-- units are installed and enabled"
    test -f /usr/lib/systemd/system/lanwatch.service
    test -f /usr/lib/systemd/system/lanwatch-helper.socket
    test "$(stat -c "%U:%G %a" /etc/lanwatch/config.toml)" = "root:lanwatch 640"
'
echo "== OK on $IMAGE ($ARCH)"
