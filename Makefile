# Convenience targets. Everything here is also a one-liner you can run by hand.
IMAGE ?= localhost/lanwatch:latest
# Distribution image the package is test-installed in (make deb-test).
DEB_TEST_IMAGE ?= docker.io/library/debian:13

.PHONY: check test clean deb deb-test container run-container helper-install

check:            ## lint, format check, types, tests
	uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q

test:
	uv run pytest -q

clean:            ## remove caches, build output and .venv (uv recreates it on the next run)
	rm -rf .venv .mypy_cache .ruff_cache .pytest_cache dist
	rm -rf debian/lanwatch debian/.build debian/.debhelper debian/files \
	  debian/debhelper-build-stamp debian/*.substvars debian/*.debhelper debian/*.debhelper.log
	find . -path ./.git -prune -o -type d \( -name __pycache__ -o -name '*.egg-info' \) -prune -exec rm -rf {} +

deb:              ## build dist/lanwatch_<version>_amd64.deb (needs debhelper, uv and network)
	dpkg-buildpackage -b -us -uc
	mkdir -p dist
	mv ../lanwatch_*_amd64.deb ../lanwatch_*_amd64.buildinfo ../lanwatch_*_amd64.changes dist/

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
