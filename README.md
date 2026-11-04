# lanwatch

Continuous auditor for your own local network. Discovers devices, tracks changes,
runs deterministic rules, keeps an always-current `overview.md`, and (from M3) uses a
local LLM to explain findings. Nothing leaves your network.

Plan and design decisions: [PLAN.md](PLAN.md).

## Status

M5. Discovery, service inventory (nmap), infra probes (DHCP, UPnP port mappings, IPv6,
mDNS), 17 deterministic rules, change detection, `overview.md`, web UI, a local LLM
(Ollama) that classifies devices, explains findings in your language, writes a daily
digest and suggests improvements, and notifications via ntfy, webhook, e-mail and Home
Assistant. Runs bare, in rootful podman, or rootless podman with a small root helper
(see `deploy/README.md`).

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

LLM: install Ollama, `ollama pull qwen3:14b`, then `lanwatch llm check`. The LLM never
produces findings or severities. It classifies devices (kind + one line), explains each
finding (what, why it matters, what to do), writes a digest at 07:00 and, on request,
structural suggestions (`lanwatch suggest`). Output is JSON-schema constrained, validated,
cached on input, and references to ids not in the input are dropped. If Ollama is down,
scanning continues and the LLM catches up later. `lanwatch llm eval` scores a model on a
device-classification golden set in `evals/`.

Infra probes (every 15 min, `lanwatch infra`): which DHCP servers answer on each segment
(two is a critical finding), UPnP devices and, for the router, every active port forward
(each one is a finding), devices with globally routable IPv6 addresses that expose
services, and mDNS service names. UPnP and mDNS facts also feed the LLM's device
classification. Version checks: a curated table of support thresholds ships with the code
(no network, no guessing); optionally nmap's `vulners` script (`scan.vulners = true`, the
one feature that calls out to the internet).

Notifications: all channels off by default. Enable one or more under `[notify]`: ntfy,
generic webhook, e-mail (SMTP), Home Assistant (a notify service plus `sensor.lanwatch_*`
entities updated every round). Findings at or above `notify.min_severity` (default
medium) are pushed once when they open, batched per round, with the LLM's one-line
summary when available. The daily digest is pushed too. `lanwatch notify --test` checks
the channels; `lanwatch notify` and the web UI show the delivery log.

Discovery backend is picked automatically: `arp-scan` (as root or with CAP_NET_RAW),
else `nmap -sn`, else a plain ping sweep plus the kernel neighbour table.

Service scans default to the `gentle` profile: nmap `-T2`, top 200 ports, light version
detection, a handful of safe scripts, port 9100 never touched (printers print probe
garbage). New devices get a light scan as soon as they appear. `lanwatch rules` lists the
rules with their effective severity.

Config: see `deploy/config.example.toml`. `lanwatch config show` prints the effective
configuration after defaults, file, env and CLI are merged.

## Deploy

See `deploy/README.md`: bare systemd, rootful podman (quadlet, host network, two
capabilities), or rootless podman plus `lanwatch-helper`, a root daemon that runs only
allowlisted scan commands over a unix socket. Ollama with ROCm has its own quadlet.

## Development

```sh
uv sync
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```
