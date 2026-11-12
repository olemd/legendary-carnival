# Deploying lanwatch

Four supported layouts. All assume Linux and a host that sits on the LAN you want to
watch (a VM behind NAT sees nothing).

## 0. Debian package (recommended on Debian and Ubuntu)

```sh
make deb                                          # needs debhelper and uv
sudo apt install ./dist/lanwatch_*_amd64.deb
```

Or install it from the apt repository, as in the Quick start of the main README.

Self-contained (own Python and libraries under `/usr/lib/lanwatch`), tested on Debian 12,
Debian 13 and Ubuntu 24.04. Releases also carry an arm64 package (Raspberry Pi and
similar), built and tested under systemd on an arm64 machine. On arm64 hardware plain
`make deb` builds it; from an amd64 machine `make deb-arm64` builds it under emulation
(podman and qemu-user-static), which works but is slow and occasionally needs a retry. After install the service is running and the web UI is on
http://127.0.0.1:8321. Config: `/etc/lanwatch/config.toml`. CLI: `sudo lanwatch ...`.

Nothing runs as root. `lanwatch.service` runs as user `lanwatch` with no capabilities;
scans that need raw sockets go over `/run/lanwatch/helper.sock` to
`lanwatch-helper.service`, which runs as its own user with `CAP_NET_RAW` and nothing else
and is started by systemd socket activation. Both are sandboxed
(`systemd-analyze security lanwatch lanwatch-helper`). Details: `debian/README.Debian`.

`make deb-test` installs the built package in a podman container running systemd and
checks all of the above.

## 1. Bare systemd (no container)

```sh
sudo apt install nmap arp-scan
sudo useradd -r -s /usr/sbin/nologin lanwatch
sudo mkdir -p /opt/lanwatch /var/lib/lanwatch && sudo chown lanwatch /var/lib/lanwatch
sudo -u lanwatch uv venv /opt/lanwatch/.venv && sudo -u lanwatch uv pip install --python /opt/lanwatch/.venv .
sudo cp deploy/lanwatch.service /etc/systemd/system/ && sudo systemctl enable --now lanwatch
```

`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` in the unit gives the unprivileged user
raw sockets for arp-scan and nmap SYN/UDP scans. lanwatch detects the ambient
`CAP_NET_RAW` and tells nmap to use it (`NMAP_PRIVILEGED`); no root needed.

## 2. Rootful podman (simplest container)

```sh
sudo podman build -t lanwatch .          # or: make container
sudo cp deploy/quadlet/lanwatch.container /etc/containers/systemd/
sudo systemctl daemon-reload && sudo systemctl start lanwatch
```

`Network=host` so it sees the LAN, `DropCapability=ALL` + `AddCapability=NET_RAW NET_ADMIN`
so it can scan and nothing more, read-only rootfs. Root inside the container is still
root on the host network namespace, which is exactly why the capability set is minimal.

## 3. Rootless podman + root helper (least privilege)

The container runs as you, with no capabilities. A small root daemon on the host
(`lanwatch-helper`) executes only allowlisted `nmap`, `arp-scan`, `ip` and `ping`
invocations whose arguments are validated against patterns. Only the nmap scripts lanwatch
itself uses may run, and targets must lie inside networks the host has an address in;
extend either with `--allow-script NAME` / `--allow-net CIDR` on the helper (or
`LANWATCH_HELPER_ALLOW_SCRIPTS` / `LANWATCH_HELPER_ALLOW_NETS`). No shell, no file
arguments, no script args.

```sh
# host: helper
sudo uv tool install .               # or: sudo make helper-install (does all four steps)
sudo ln -s /root/.local/bin/lanwatch-helper /usr/local/bin/lanwatch-helper
sudo groupadd -f lanwatch && sudo usermod -aG lanwatch $USER   # re-login afterwards
sudo cp deploy/lanwatch-helper.service /etc/systemd/system/
sudo systemctl enable --now lanwatch-helper

# user: container
podman build -t lanwatch .
mkdir -p ~/.local/share/lanwatch ~/.config/lanwatch ~/.config/containers/systemd
cp deploy/quadlet/lanwatch-rootless.container ~/.config/containers/systemd/lanwatch.container
systemctl --user daemon-reload && systemctl --user start lanwatch
loginctl enable-linger $USER
```

Inside the container everything that needs privileges goes through the socket
(`LANWATCH_SCAN__HELPER_SOCKET`). `ip -j addr` and the web UI run locally.

Why not just `--cap-add` in rootless mode: with `--network host` the container shares the
host network namespace but not the host user namespace, and the kernel grants raw-socket
capabilities only to the user namespace that owns the network namespace. So rootless +
host network + raw sockets is a dead end; a helper is the honest fix.

## Ollama on the RX 7900 XTX

Either install Ollama natively (`curl -fsSL https://ollama.com/install.sh | sh`, it
detects ROCm) or use `deploy/quadlet/ollama.container`. Then:

```sh
ollama pull qwen3.8:27b
lanwatch llm check
lanwatch llm eval                          # both suites, default model
lanwatch llm eval --model gemma4:26b       # compare before switching llm.model
lanwatch llm eval --suite chat             # tool-calling only
```

Two suites: `classify` (19 device fingerprints -> expected kind) and `chat` (8 questions
against a fixed network: must the right tools be called, must actions stay unused unless
asked, must the answer contain the facts). A ~27B model at Q4 is 16-18 GB, which leaves
room for the 16k chat context on 24 GB. If a model turns out not to support tools in
Ollama, the chat falls back to pasting the inventory into the prompt and says so in the
log. Pick with the eval, not by feel.

If lanwatch runs on a different host than the GPU, set `llm.base_url` to that host and
bind Ollama to a LAN address (`OLLAMA_HOST=0.0.0.0`). Still local, nothing leaves the LAN.

## KoboldCpp instead of Ollama

Set `llm.backend = "koboldcpp"` and point `llm.base_url` at the instance (port 5001 by
default). lanwatch then uses KoboldCpp's OpenAI-compatible API, with the JSON schema
enforced as a grammar. `lanwatch llm check` and `lanwatch llm eval` work the same. What
differs:

- KoboldCpp serves the one model it was started with and ignores the model name in a
  request. `llm.model` is only a label (web UI, cache key); change it when you load another
  model so cached answers are not reused. `llm eval --model` cannot switch models.
- The context window is set at launch (`--contextsize`), not per request: `num_ctx`,
  `chat_num_ctx` and `keep_alive` are ignored. Start it with at least 16384 for the chat.
- Replies are capped by `--defaultgenamt` (2048 tokens unless changed). A long digest that
  gets cut off shows up in the log as `done_reason=length`.
- Start KoboldCpp with `--jinja` to have thinking switched off for models like Qwen3;
  without it they think first, which is slower but still works.
- An instance protected with `--password` is not supported yet.

## Two servers: a fallback

To use both, make one the primary and the other the fallback:

```toml
[llm]
backend = "koboldcpp"
base_url = "http://gpu-box:5001"
model = "gemma4-12b"

[llm.fallback]
backend = "ollama"
base_url = "http://localhost:11434"
model = "qwen3.8:27b"
```

The fallback is used when the primary cannot be reached (host off, server stopped) or has
no model, and the log says so. The primary is tried again on the next scan round or
question. A slow or failing answer from a reachable primary does not switch servers.
Everything else in `[llm]` (timeout, temperature, language) applies to both.
`lanwatch llm check` and the status page show both servers; the check fails only when
neither is usable. Answers are cached per model that wrote them: what the fallback answered
is reused while the primary stays down, and asked again of the primary once it is back.
While the primary is down, each round spends one call finding that out.

## Config

`/etc/lanwatch/config.toml` (or `~/.config/lanwatch/config.toml` rootless). Every key
optional; see `config.example.toml` (the package installs it as
`/etc/lanwatch/config.toml.default`). `lanwatch config show` prints the merged result.
