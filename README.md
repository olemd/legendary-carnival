# lanwatch

Continuous auditor for your own local network. Discovers devices, tracks changes,
runs deterministic rules, keeps an always-current `overview.md`, and (from M3) uses a
local LLM to explain findings. Nothing leaves your network.

Plan and design decisions: [PLAN.md](PLAN.md).

## Status

M1. Discovery, inventory, change detection, overview. No service scanning or LLM yet.

## Quick start

```sh
uv sync
uv run lanwatch scan          # one round; the first round is the baseline
uv run lanwatch devices
uv run lanwatch overview
uv run lanwatch run           # keep running, discovery every 5 min
```

Discovery backend is picked automatically: `arp-scan` (as root or with CAP_NET_RAW),
else `nmap -sn`, else a plain ping sweep plus the kernel neighbour table.

Config: see `deploy/config.example.toml`. `lanwatch config show` prints the effective
configuration after defaults, file, env and CLI are merged.

## Deploy

`deploy/lanwatch.service` runs it as an unprivileged user with the two capabilities
scanning needs.

## Development

```sh
uv sync
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```
