# lanwatch

Continuous auditor for your own local network. Discovers devices, tracks changes,
runs deterministic rules, keeps an always-current `overview.md`, and (from M3) uses a
local LLM to explain findings. Nothing leaves your network.

Plan and design decisions: [PLAN.md](PLAN.md).

## Status

M2. Discovery, service inventory (nmap), ten deterministic rules, change detection,
`overview.md`, and a web UI. No LLM yet (M3).

## Quick start

```sh
sudo apt install nmap arp-scan      # arp-scan optional, nmap needed for service inventory
uv sync
uv run lanwatch scan                # discovery + service inventory; first round is the baseline
uv run lanwatch devices
uv run lanwatch findings
uv run lanwatch run                 # daemon: discovery 5 min, inventory 1 h, deep weekly, web UI
```

Web UI: http://127.0.0.1:8321 while `run` (or `lanwatch web`) is active. Loopback only by
default; to reach it from another machine set `web.host` and `web.password`.

Discovery backend is picked automatically: `arp-scan` (as root or with CAP_NET_RAW),
else `nmap -sn`, else a plain ping sweep plus the kernel neighbour table.

Service scans default to the `gentle` profile: nmap `-T2`, top 200 ports, light version
detection, a handful of safe scripts, port 9100 never touched (printers print probe
garbage). New devices get a light scan as soon as they appear. `lanwatch rules` lists the
rules with their effective severity.

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
