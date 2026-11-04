# Deploying lanwatch

Three supported layouts. All assume Linux and a host that sits on the LAN you want to
watch (a VM behind NAT sees nothing).

## 1. Bare systemd (no container)

```sh
sudo apt install nmap arp-scan
sudo useradd -r -s /usr/sbin/nologin lanwatch
sudo mkdir -p /opt/lanwatch /var/lib/lanwatch && sudo chown lanwatch /var/lib/lanwatch
sudo -u lanwatch uv venv /opt/lanwatch/.venv && sudo -u lanwatch uv pip install --python /opt/lanwatch/.venv .
sudo cp deploy/lanwatch.service /etc/systemd/system/ && sudo systemctl enable --now lanwatch
```

`AmbientCapabilities=CAP_NET_RAW CAP_NET_ADMIN` in the unit gives the unprivileged user
raw sockets for arp-scan and nmap SYN/UDP scans.

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

The container runs as you, with no capabilities. A ~150-line root daemon on the host
(`lanwatch-helper`) executes only allowlisted `nmap`, `arp-scan`, `ip` and `ping`
invocations whose arguments are validated against patterns; targets must be IP
addresses or CIDRs. No shell, no file arguments, no script args.

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
ollama pull qwen3:14b
lanwatch llm check
lanwatch llm eval                          # golden set, default model
lanwatch llm eval --model qwen3:32b        # compare before switching llm.model
```

24 GB VRAM fits `qwen3:32b` at Q4 with 8k context; `qwen3:14b` leaves headroom and
answers in a few seconds. Pick with the eval, not by feel.

If lanwatch runs on a different host than the GPU, set `llm.base_url` to that host and
bind Ollama to a LAN address (`OLLAMA_HOST=0.0.0.0`). Still local, nothing leaves the LAN.

## Config

`/etc/lanwatch/config.toml` (or `~/.config/lanwatch/config.toml` rootless). Every key
optional; see `config.example.toml`. `lanwatch config show` prints the merged result.
