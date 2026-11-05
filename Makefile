# Convenience targets. Everything here is also a one-liner you can run by hand.
IMAGE ?= localhost/lanwatch:latest

.PHONY: check test clean container run-container helper-install

check:            ## lint, format check, types, tests
	uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest -q

test:
	uv run pytest -q

clean:            ## remove caches, build output and .venv (uv recreates it on the next run)
	rm -rf .venv .mypy_cache .ruff_cache .pytest_cache dist
	find . -path ./.git -prune -o -type d \( -name __pycache__ -o -name '*.egg-info' \) -prune -exec rm -rf {} +

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
