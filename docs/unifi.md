# lanwatch and a UniFi controller

With a UniFi Network controller on the LAN (a UniFi OS console such as the Express, Dream
Machine or Cloud Gateway, a Cloud Key, or UniFi OS Server on your own hardware), lanwatch
can read what the controller knows and no scan can see:

- per client: wired or wireless, which access point or switch it hangs off, guest or not,
  the name set in the controller, when it connected, and which network (VLAN) it is on;
- the networks and SSIDs that exist, with VLAN ids, subnets and isolation settings;
- the UniFi devices themselves: state, firmware, whether an update is pending, ports and
  radios, and how they are chained together.

That feeds three rules (`net.iot-on-main-network`, `inventory.unifi-only`,
`net.unifi-device-offline`), sharpens the flat-network note, puts UniFi firmware under the
existing `device.firmware-outdated` rule, and draws the **Topology** page.

Everything lanwatch does is read-only, over HTTPS, on the LAN: none of the API's write
endpoints are used. The key itself is not read-only, though; see section 1.

## 1. Create an API key on the console

UniFi Network 9.3 or later. In the Network application on the console's local web UI, open
the Integrations page and choose **Create API Key**. Name it `lanwatch`. The key is shown
once.

Where that page sits in the menus has moved between Network versions (**Settings → Control
Plane → Integrations** in 9.x; in 10.x the Control Plane section may only show Updates,
Backups, Console and Push Notifications). The address works in all of them:
`https://<console>/network/default/integrations`, with your site's name in place of
`default` if it has another.

**Treat the key like the router's admin password.** UniFi does not make read-only keys: a
key has every right the account that created it has, and the same API has endpoints that
block clients, change networks and edit the firewall. lanwatch calls none of them, but
whoever holds the key could. Two things limit the damage of a leak:

- Create the key from a dedicated local account with the lowest role that may create keys
  (a *View Only* or *Site Admin* role rather than the owner account), named after lanwatch
  so a revocation is obvious.
- Keep it in `/etc/lanwatch/config.toml` only. The package installs that file readable by
  root and the service user; `lanwatch config show` prints `***` for it.

## 2. Configure lanwatch

In `/etc/lanwatch/config.toml`:

```toml
[unifi]
enabled = true
url = "https://192.168.1.1"       # the console; lanwatch appends the API path itself
api_key = "paste the key here"
verify_tls = false                # see TLS below
```

Then:

```sh
sudo systemctl restart lanwatch
sudo lanwatch unifi               # reads the controller now and prints what it got
```

The infra round reads the controller every 15 minutes (`schedule.infra_interval_s`) from
then on. The **Infra** page gets a *UniFi controller* section and the **Topology** page
fills in.

### TLS

Consoles ship a self-signed certificate, so `verify_tls = true` (the default) fails until
you do one of two things:

- **Pin the console's certificate** (recommended): export it and point lanwatch at it.
  ```sh
  openssl s_client -connect 192.168.1.1:443 -showcerts </dev/null 2>/dev/null \
    | openssl x509 -outform PEM | sudo tee /etc/lanwatch/unifi.pem >/dev/null
  ```
  ```toml
  [unifi]
  ca_file = "/etc/lanwatch/unifi.pem"
  ```
  lanwatch then accepts exactly that certificate. When the console gets a new one (a
  firmware reset, a custom certificate), repeat the export.
- **Skip verification**: `verify_tls = false`. The link is still encrypted, but lanwatch
  cannot tell the console from something answering in its place. On a home LAN most people
  accept that; the key is the only thing at stake.

The two are mutually exclusive: `ca_file` with `verify_tls = false` is a config error.

### Other keys

| Key | Default | Meaning |
|---|---|---|
| `site` | first site | Site id or name when the controller has several. |
| `adopt_names` | `true` | A device without a name in lanwatch gets the name set in the controller. A name set in lanwatch is never overwritten, and a controller "name" that is just the hostname is ignored. |

## 3. What you get

**Device pages.** A *UniFi* row: name, wired/wireless, guest, via which device, which
network and VLAN, and the SSIDs on that network. A UniFi device's page gets a *UniFi device*
row (model, state, uplink, ports up, radios) and a *Firmware* row that says *update
available* when the controller has one pending.

**Infra page.** Controller version and site, the networks with VLAN, subnet, SSIDs,
isolation and internet access, the SSIDs with their type, and the UniFi devices with state,
firmware and client counts. Plus how many clients lanwatch has never seen itself.

**Topology page.** Gateway on the left, access points and switches beside it, clients under
the device they hang off, each labelled with its network. The same tree as a list below.

**Rules.**

| Rule | Severity | When |
|---|---|---|
| `net.iot-on-main-network` | medium | An IoT-class device is on the default network while another network, or an IoT-optimised SSID, exists. Silent on a flat network. |
| `inventory.unifi-only` | info | The controller lists a client lanwatch has never seen: another VLAN, or client isolation. |
| `net.unifi-device-offline` | high | An adopted device is offline, isolated or has its connection interrupted. Resolves when it is back. |
| `device.firmware-outdated` | low | Now also fires for UniFi devices with a pending update. |
| `improvement.flat-network` | info | Groups by the controller's networks instead of guessing a /24. |

`lanwatch unifi` prints the same summary on the command line and lists the clients the
controller sees but lanwatch does not.

## 4. What the API key cannot tell

The Integration API reports no SSID, signal strength or switch port per client. Those exist
only in the controller's older local API, which needs an admin password rather than a key
and is not used by lanwatch. The network a client is on is derived from its address against
the gateway-managed subnets, so a client without an address, or on a network the gateway
does not manage, shows no network.

UniFi OS Server (the self-hosted UniFi OS, on a Linux machine or in a container) serves the
API like a console and works as described here; behind a reverse proxy with a public
certificate, `verify_tls = true` works without `ca_file`. The older standalone Network
application (no UniFi OS, normally on port 8443) serves the API under a different path and
is not supported yet.

## Troubleshooting

- **`the controller rejected the API key`** (401/403): wrong or revoked key, or the account
  behind it lost its rights. Make a new key.
- **certificate error**: the console's certificate is self-signed. Pin it with `ca_file` or
  set `verify_tls = false` (section 2).
- **`no site called …`**: `site` does not match the id, name or internal reference of a
  site on the controller. Leave it unset for a single-site console.
- **The controller is listed as "not read"** on the Infra page: the last fetch failed; the
  page shows the previous state and the error. `lanwatch unifi -v` repeats it with details.
- **Clients the controller sees but lanwatch does not**: expected for other VLANs (lanwatch
  scans the segments the host sits on) and for guest or isolated clients. Accept the finding
  if that is the design. A client with an address on a scanned subnet gets a second,
  slower ping each discovery round (`scan.recheck_silent`); if it answers that, it is
  recorded like any other device and the finding resolves.
- **A phone shows up twice**: a randomised MAC on one side and the controller's record on
  the other. Merge the entries on the device page; lanwatch then matches both addresses.
