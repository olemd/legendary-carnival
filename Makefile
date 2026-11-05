# Convenience targets. Everything here is also a one-liner you can run by hand.
IMAGE ?= localhost/lanwatch:latest
DEB_ARCH := $(shell dpkg --print-architecture 2>/dev/null)
# Distribution image the package is test-installed in (make deb-test).
DEB_TEST_IMAGE ?= docker.io/library/debian:13

.PHONY: check test clean deb deb-arm64 deb-test container run-container helper-install

check:            ## lint, format check, types, tests
	uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q

test:
	uv run pytest -q

clean:            ## remove caches, build output and .venv (uv recreates it on the next run)
	rm -rf .venv .mypy_cache .ruff_cache .pytest_cache dist
	rm -rf debian/lanwatch debian/.build debian/.debhelper debian/files \
	  debian/debhelper-build-stamp debian/*.substvars debian/*.debhelper debian/*.debhelper.log
	find . -path ./.git -prune -o -type d \( -name __pycache__ -o -name '*.egg-info' \) -prune -exec rm -rf {} +

deb:              ## build dist/lanwatch_<version>_<arch>.deb for this machine (needs debhelper, uv, network)
	dpkg-buildpackage -b -us -uc
	mkdir -p dist
	mv ../lanwatch_*_$(DEB_ARCH).deb ../lanwatch_*_$(DEB_ARCH).buildinfo ../lanwatch_*_$(DEB_ARCH).changes dist/

# The build runs the bundled Python, so it happens in an arm64 container under emulation
# (needs podman and qemu-user-static with binfmt). The source is copied inside the
# container; only the finished .deb comes back out. -d: nothing is compiled, so the
# build-essential dependency dpkg would otherwise insist on is not installed there.
deb-arm64:        ## build dist/lanwatch_<version>_arm64.deb in an emulated container
	BUILDAH_FORMAT=docker podman build --arch arm64 -f debian/Containerfile.build \
	  --build-arg BUILD_DATE="$$(date -u +%Y-%m-%dT%H:%M:%SZ)" \
	  --build-arg GIT_REVISION="$$(git describe --always --dirty)" \
	  -t localhost/lanwatch-debbuild:arm64 debian
	mkdir -p dist
	podman run --rm --arch arm64 -v "$(CURDIR):/src:ro" -v "$(CURDIR)/dist:/out" \
	  localhost/lanwatch-debbuild:arm64 sh -ec '\
	    mkdir lanwatch && cd lanwatch && \
	    tar -C /src --exclude=./.git --exclude=./.venv --exclude=./dist --exclude=./debian/lanwatch \
	        --exclude=./debian/.build --exclude=./debian/.debhelper -cf - . | tar -xf - && \
	    dpkg-buildpackage -b -us -uc -d && cp ../lanwatch_*_arm64.deb /out/'

deb-test:         ## install the built package in a systemd container and exercise it (needs podman)
	tests/deb/e2e.sh $(DEB_TEST_IMAGE)

container:        ## build the image with podman
	podman build -t $(IMAGE) .

run-container:    ## one-off foreground run (rootful, host network, scan capabilities only)
	podman run --rm -it --network host --cap-drop ALL --cap-add NET_RAW --cap-add NET_ADMIN \
	  -v /var/lib/lanwatch:/var/lib/lanwatch:Z -v /etc/lanwatch:/etc/lanwatch:ro,Z $(IMAGE) run

helper-install:   ## install lanwatch-helper for rootless setups (run as root)
	uv tool install --force .
	ln -sf $$(uv tool dir)/lanwatch/bin/lanwatch-helper /usr/local/bin/lanwatch-helper
	groupadd -f lanwatch
	install -m 644 deploy/lanwatch-helper.service /etc/systemd/system/
	systemctl daemon-reload && systemctl enable --now lanwatch-helper
