# lanwatch

Continuous auditor for your own local network. Discovers devices, tracks changes,
runs deterministic rules, keeps an always-current `overview.md`, and (from M3) uses a
local LLM to explain findings. Nothing about your network leaves it: the only outbound
requests fetch public version and vendor lists, and `online = false` turns those off. The
opt-in exposure check is the exception: it sends the public address to Shodan's InternetDB.

Plan and design decisions: [PLAN.md](PLAN.md).

## Status

M6, all planned milestones delivered. Discovery, service inventory (nmap), infra probes
(DHCP, UPnP port mappings, IPv6, mDNS), 27 deterministic rules, change detection with an
event timeline, `overview.md`, web UI with search and an inventory chat, a local LLM
(Ollama) that classifies devices, explains findings in your language, writes a daily
digest and suggests improvements, and notifications via ntfy, webhook, e-mail and Home
Assistant. Runs from a Debian package, bare, in rootful podman, or rootless podman with a small helper
(see `deploy/README.md`).

## Quick start

On Debian or Ubuntu, install the package. It bundles its own Python, starts the service
and runs nothing as root. Each release carries an amd64 and an arm64 `.deb`:

```sh
gh release download -R olemd/legendary-carnival -p "lanwatch_*_$(dpkg --print-architecture).deb"
sudo apt install ./lanwatch_*.deb
```

The service is now scanning the networks this machine is attached to: discovery every
5 minutes, service inventory hourly, a deep scan weekly. The first round is the baseline;
changes and findings accumulate from there.

```sh
sudo lanwatch devices               # the CLI works on the service's database
sudo lanwatch findings
sudo lanwatch config show           # effective configuration
journalctl -u lanwatch -f
```

Web UI: http://127.0.0.1:8321 on the host, loopback only by default. To reach it from
another machine set `web.host` and `web.password` in `/etc/lanwatch/config.toml`, then
`sudo systemctl restart lanwatch`. Every key in that file is optional; the reference with
every key, its default and what it does is `/etc/lanwatch/config.toml.default`.

From a checkout, without installing anything but the scanners:

```sh
sudo apt install nmap arp-scan      # arp-scan optional, nmap needed for service inventory
uv sync
uv run lanwatch scan                # discovery + service inventory; first round is the baseline
uv run lanwatch devices
uv run lanwatch findings
uv run lanwatch run                 # daemon: discovery 5 min, inventory 1 h, deep weekly, web UI
```

Web UI from a checkout: http://127.0.0.1:8321 while `run` (or `lanwatch web`) is active.

LLM: install Ollama, `ollama pull qwen3.8:27b` (or `gemma4:26b`), then `lanwatch llm check`. The LLM never
produces findings or severities. It classifies devices (kind + one line), explains each
finding (what, why it matters, what to do), writes a digest at 07:00 and, weekly or on request,
structural suggestions (`lanwatch suggest`, or "Run now" on the status page). Output is JSON-schema constrained, validated,
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

Timeline: every state change is an event (device new/renamed/classified/IP change,
service opened/closed, finding opened/resolved/acked/reopened, DHCP server or port mapping
appeared/disappeared, device online/offline). `lanwatch timeline`, `/timeline` with
filters, and a history section per device. `lanwatch search` and the search box cover
devices, services and findings.

Chat: `/chat` and `lanwatch ask "..."` answer questions about the network through tool
calling. Read tools query the live inventory (devices, services, findings, timeline,
infrastructure, rules); three action tools (acknowledge a finding, name a device, run a
scan) exist and the prompt only allows them when you ask for that action. Every tool call
is returned with the answer and shown under it, so you can see what the model looked up or
did. Actions can be switched off per request (`--no-actions`, or the checkbox). Chat
actions are logged as `chat.action` events in the timeline.

Notifications: all channels off by default. Enable one or more under `[notify]`: ntfy,
generic webhook, e-mail (SMTP), Home Assistant (a notify service plus `sensor.lanwatch_*`
entities updated every round; tapping a notification opens lanwatch and a button accepts
the finding, see [docs/home-assistant.md](docs/home-assistant.md)). Findings at or above
`notify.min_severity` (default medium) are pushed once when they open, batched per round,
with the LLM's one-line summary when available. The daily digest is pushed too.
`lanwatch notify --test` checks the channels; `lanwatch notify` and the web UI show the
delivery log.

Discovery backend is picked automatically: `arp-scan` (as root or with CAP_NET_RAW),
else `nmap -sn`, else a plain ping sweep plus the kernel neighbour table. Addresses that
stay silent but should be there (online in the previous round, or listed by the UniFi
controller) get a second, slower ping in the same round (`scan.recheck_silent`), so a
power-saving Wi-Fi device that sleeps through the scan is not reported offline; only a
reply counts.

Service scans default to the `gentle` profile: nmap `-T2`, top 200 ports, light version
detection, a handful of safe scripts, port 9100 never touched (printers print probe
garbage). A device that cannot take a scan at all goes in `scan.skip_hosts`: it is
discovered and tracked like the rest, but nmap never touches it. New devices get a light
scan as soon as they appear. `lanwatch rules` lists the rules with their effective severity.

Day to day, in the web UI:

- **Status** shows each scheduled job (running, last result, next run) with a "Run now"
  button, whether scans have raw-socket privileges, and whether the LLM is reachable. A
  header indicator shows when a scan is in progress.
- **Devices** can be renamed, re-classified, merged (one device seen under two MAC
  addresses, typically a phone with a private MAC) and forgotten. Mark a device as watched
  to get a finding when it stays offline.
- **Findings** can be acknowledged, accepted for good with a reason (a per-device exception
  to a rule) and reopened.
- Network identity rules flag two devices answering for one IP, a gateway, DHCP or DNS
  address that changes MAC, and a DHCP server that starts announcing different DNS, NTP or
  router settings.

Signs of someone looking around or impersonating others (no mirror port needed):

- **Decoy ports** (`[decoy]`): listeners on ports this machine does not use. A device that
  connects is scanning the network and becomes a finding. Ports already in use are skipped.
- **ARP listener**: hears ARP traffic between scans, for spoofing (two MACs fighting over
  an address) and sweeps (one device asking for most of the subnet).
- **Decoy name lookups**: asks for a host name that does not exist over LLMNR, mDNS and
  NetBIOS. Whatever answers is a poisoning tool.
- **New IPv6 routers**: a router advertisement from a device that was not a router before.

Hygiene checks:

- **Firmware** (`[firmware]`, daily, `lanwatch firmware`): the version Home Assistant,
  ESPHome, Shelly, Tasmota, Pi-hole and Jellyfin devices report, and whether a newer release
  exists. Reading versions stays on the LAN; the latest release is looked up at the vendor
  or on GitHub unless `online = false`.
- **UniFi controller** (`[unifi]`, read-only, every infra round, `lanwatch unifi`): with a
  UniFi OS console on the LAN, each client's uplink device, wired/wireless, guest flag,
  controller name and network/VLAN; the networks, SSIDs and UniFi devices with pending
  firmware; a **Topology** page; and rules for IoT devices on the main network, clients only
  the controller sees, and UniFi devices offline. API key, nothing leaves the LAN. See
  [docs/unifi.md](docs/unifi.md).
- **Internet exposure** (`[exposure]`, off by default, daily, `lanwatch exposure`): the
  public address looked up in Shodan's InternetDB, which scans the whole internet. Ports that
  answer from outside become a finding, critical when Shodan also matched the service to
  published vulnerabilities. The one check that tells a third party the network's public
  address, hence opt-in.
- **Latency** (`[latency]`): a few pings to the gateway each discovery round. The dashboard
  shows a day's trend, and sustained packet loss becomes a finding. Add an internet address
  to the targets to measure the path out as well.
- **MAC vendors** (`[oui]`): devices the scanner cannot name get their vendor from a
  fresher IEEE registry, downloaded weekly, or from nmap's installed copy with `online = false`.
- **DNS filtering** (`scan.dns_filter_check`, off by default): whether the resolver DHCP
  hands out blocks ads or known-malicious test names.

History is pruned daily (`[store] keep_*_days`), so the database stops growing.

Config: see `deploy/config.example.toml`, installed by the package as
`/etc/lanwatch/config.toml.default` next to your own `config.toml`, which ships as an empty
stub so upgrades never have to merge it. `lanwatch config show` prints the effective
configuration after defaults, file, env and CLI are merged.

## Deploy

The Debian package (see Quick start) is the recommended layout. To build it yourself:

```sh
make deb                                          # needs debhelper and uv
sudo apt install ./dist/lanwatch_*_amd64.deb
```

Other layouts are in `deploy/README.md`: bare systemd, rootful podman (quadlet, host
network, two capabilities), or rootless podman plus `lanwatch-helper`, a small daemon that
runs only allowlisted scan commands over a unix socket. Ollama with ROCm has its own quadlet.

## Development

```sh
uv sync
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```
