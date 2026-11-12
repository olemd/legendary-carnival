# lanwatch and the router (and other devices) over SNMPv3

Most routers and firewalls answer SNMP, and the router knows things no scan from one host
on the LAN can see. lanwatch reads them with **SNMPv3 only**, with authentication and
encryption (`authPriv`), and only reads.

Why v3 only: SNMPv1 and v2c send the community string in clear text on every request, and
anyone who has it, or sniffs it, gets the same view lanwatch has. A router answering on
`public` is itself worth fixing. MD5 and DES are refused for the same reason. SHA-1 is
allowed for authentication: SNMPv3 uses it as an HMAC, which the known SHA-1 collision
attacks do not break, and some agents (UniFi) offer nothing else. Prefer SHA-256 where
the agent has it.

What lanwatch reads:

- the system group: name, model and software (`sysDescr`), vendor (`sysObjectID`), uptime;
- the router's ARP and IPv6 neighbour table (IP-MIB), from any router;
- on Juniper, the leases its own DHCP server has handed out (JUNIPER-JDHCP-MIB).

What it does with them:

- **Never presence.** A router keeps an ARP entry, and a lease, for many minutes after a
  device has gone, so neither can say a device is online. Addresses the router knows and
  the discovery scan missed are added to the slower ping of the recheck
  (`scan.recheck_silent`): only a reply makes them online.
- **A second view of who holds each address.** When the router ties an address to
  another MAC than the one that answered lanwatch, in two reads in a row, that is the
  `net.router-arp-mismatch` finding: an address conflict, or a device that has told the
  router it is someone else (ARP spoofing). Critical for the gateway, DHCP and DNS.
- **Facts on each device:** that the router has it in its ARP table and on which
  interface, and (Juniper) whether it holds a DHCP lease and since when. A device in the
  ARP table without a lease has its address set by hand, or from another DHCP server.

Interface state and vendor health data follow.

Polling is SNMPv3 only. The one exception is the
[default-credential probe](#the-default-credential-probe) below, which speaks v1/v2c only
to test the well-known defaults, never with real credentials.

## 1. Create a read-only SNMPv3 user on the router

Pick two random passwords (8 characters or more, no spaces), for example with
`openssl rand -hex 16`, one for authentication and one for encryption.

### Junos (SRX, EX, MX)

Check first that your release has SHA-256: `set snmp v3 usm local-engine user lanwatch ?`
in configuration mode should list `authentication-sha256`.

Junos turns each password into a key bound to the engine id that is *active* when you
type it. If the router does not have `engine-id use-mac-address` yet, set and commit that
on its own first; set in the same commit as the passwords, they end up bound to the old
engine id and every request fails with "Authentication failure".

```
set snmp engine-id use-mac-address
commit
```

Then:

```
set snmp view lanwatch oid 1.3.6.1.2.1.1 include
set snmp view lanwatch oid 1.3.6.1.2.1.2 include
set snmp view lanwatch oid 1.3.6.1.2.1.4 include
set snmp view lanwatch oid 1.3.6.1.2.1.25 include
set snmp view lanwatch oid 1.3.6.1.2.1.31 include
set snmp view lanwatch oid 1.0.8802.1.1.2 include
set snmp view lanwatch oid 1.3.6.1.4.1.2636.3 include
set snmp v3 usm local-engine user lanwatch authentication-sha256 authentication-password "AUTH-PASSWORD"
set snmp v3 usm local-engine user lanwatch privacy-aes128 privacy-password "PRIV-PASSWORD"
set snmp v3 vacm security-to-group security-model usm security-name lanwatch group lanwatch
set snmp v3 vacm access group lanwatch default-context-prefix security-model usm security-level privacy read-view lanwatch
```

The view limits the user to what lanwatch reads: system, interfaces, IP (ARP), host
resources, the interface extensions, LLDP and Juniper's own MIBs (health, DHCP, security
policies and NAT). Junos stores the passwords as keys localized to the router's engine id,
so `show configuration snmp` shows `$9$` strings, not the passwords. Changing the engine id
later invalidates them; `use-mac-address` keeps it stable across reconfiguration.

SNMP also has to be allowed in by the security zone on an SRX
(`host-inbound-traffic system-services snmp` on the LAN interface).

On an SRX, `commit confirmed 5` first, then test from the lanwatch host (section 3) before
the final `commit`. When nothing else polls v2c any more, remove the community:
`delete snmp community public`. `show snmp statistics` twice a few minutes apart tells you
whether anything still does.

### Junos extras

A device that answers as Juniper (any device under `[snmp.devices]`, the router too) gets
a few more reads, with nothing to configure and nothing to change on the device. They
cover:

- chassis alarms;
- health: routing engine CPU, memory and temperature, the state of each FRU, and how
  full the flash partitions are;
- the commit log, and whether a rescue config is saved;
- security sessions against the maximum;
- screen counters per zone;
- the DHCP server's decline counter;
- licences.

They show on the device page. Rules: `junos.chassis-alarm`, `junos.storage-full`,
`junos.fru-not-online`, `junos.session-table-full`, `junos.config-changed` (one finding
per commit, resolved by itself after a week), `junos.no-rescue-config` and `dhcp.declines-rising`.

What a device does not have (no security sessions on an EX switch, no DHCP server, no
chassis cluster) is left out quietly. The reads need `1.3.6.1.4.1.2636.3` and
`1.3.6.1.2.1.25` (storage names) in the user's view; the `lanwatch` view from section 1
has both.

### UniFi gateways

UniFi Network has SNMPv3 with a username and one password, and fixed algorithms: SHA-1
for authentication and AES-128 for encryption. Where to switch it on has moved between
Network versions; Ubiquiti's article "SNMP Monitoring in UniFi Network"
(https://help.ui.com/hc/en-us/articles/33502980942615) has the current place. In
lanwatch, use the one password for both:

```toml
[snmp.devices.gw]
router = true
user = "lanwatch"
auth_protocol = "SHA"       # SHA-1; UniFi has nothing newer
auth_password = "..."
priv_protocol = "AES"
priv_password = "..."       # the same password again
```

With a UniFi gateway, the `[unifi]` integration (docs/unifi.md) already lists the
clients; SNMP adds the gateway's own ARP table and the cross-check against it.

### Other routers

Any SNMPv3 agent works. Create a user with the authPriv security level, SHA-256 (or
SHA-1 if the agent has nothing newer) and AES, and a read-only view that includes at
least `1.3.6.1.2.1.1` (system). Agents that only speak v1 or v2c (airOS on airMAX radios
answers v1 only) cannot be read.

## 2. Configure lanwatch

In `/etc/lanwatch/config.toml`, every device read over SNMP is a table under
`[snmp.devices]`, named by you. The name is how lanwatch shows the device. `router = true`
marks the router, at most one; lanwatch also reads its ARP table and DHCP leases.

```toml
[snmp.devices.fw]
router = true
host = "192.168.1.1"        # the router only may leave it out: this host's default gateway
user = "lanwatch"
auth_protocol = "SHA-256"   # the default
auth_password = "..."
priv_protocol = "AES"       # the default; AES-128, Junos has no other AES variant
priv_password = "..."
# timeout_s = 5
# enabled = false           # keep the table but stop reading the device
```

Nothing is shared between devices: each table holds its device's whole login, since a
user and its passwords belong to the device they were made on. 0.8.0's form, the
router's login straight under `[snmp]` with `enabled = true`, is still read, as a device
named `router`; `lanwatch config show` prints it in the new form.

`enabled` under `[snmp]` is the switch for all of it: `enabled = false` reads none of
the devices, whatever their own tables say, and their logins are not checked. It is on
by default, so listing a device is enough.

`lanwatch config show` prints `***` for both passwords. lanwatch never puts them on a
command line: each read writes a private snmp.conf in a temporary directory, readable only
by the service, and removes it afterwards.

The package recommends the `snmp` package, which has `snmpbulkwalk`. `apt install
./lanwatch_*.deb` installs it along; `dpkg -i` and `--no-install-recommends` do not, and
then `apt install snmp` does. Without it, `lanwatch snmp` and the log say so.

MIB files are not needed: lanwatch asks for numeric output and knows the few OIDs it reads.
Debian's `snmp-mibs-downloader` (non-free, and it downloads the MIBs from the internet when
installed) only makes `snmpwalk` output readable when you query the router by hand.

### More devices than the router

Other devices that answer SNMPv3 (a UPS management card, a switch, another firewall) get
a table each, like the router but without `router = true`. lanwatch reads what each one
says it is (the system group) every infra round, keeps its state, and shows them all on
the infra page (`/infra#snmp`). A router is not needed for them.

```toml
[snmp.devices.ups]
host = "192.168.1.20"
user = "lanwatch"
auth_protocol = "SHA"       # SHA-1: the newest some agents (APC NMC2, UniFi) offer
auth_password = "..."
priv_password = "..."

[snmp.devices.core-switch]
host = "192.168.1.30"
user = "monitor"
auth_password = "..."
priv_password = "..."
```

The same rules apply to every login: authPriv, no MD5 or DES, passphrases of 8 characters
or more. Each device is read on its own; one that fails keeps its last good state and
does not stop the others.

A UPS management card listed this way is recognised and read in full: power, battery,
self-test, firmware, findings and graphs. See [ups.md](ups.md).

## 3. Check it

```
sudo lanwatch snmp
```

prints what every device under `[snmp.devices]` says it is, how long it has been up,
and for the router how many ARP entries and leases it has. It exits with an error if any
of them could not be read. After that the infra job reads them every round
(`schedule.infra_interval_s`, 15 minutes by default).

To test the user without lanwatch, from the same host:

```
snmpget -v3 -l authPriv -u lanwatch -a SHA-256 -A AUTH-PASSWORD -x AES -X PRIV-PASSWORD \
  192.168.1.1 1.3.6.1.2.1.1.5.0
```

(this puts the passwords in your shell history and the process list, so only for a test).

## Checks on every device

Two findings apply to every device under `[snmp.devices]`, the router included:

- **Clock skew** (`snmp.clock-skew`): each read also asks for the device's clock
  (`hrSystemDate` from HOST-RESOURCES-MIB, or the APC card's own clock) and compares it
  with lanwatch's, at the middle of the read. More than 2 minutes off is low, more than
  an hour medium. A device that gives local time without a zone (the APC card) and is off
  by whole hours is reported as a time zone or summer time setting. A device that answers
  neither clock is simply not checked.
- **Not readable** (`snmp.unreachable`): 3 failed reads in a row; medium for the router,
  low otherwise. "Never read" usually means a login or access-list problem: see below.

Both resolve by themselves once the device is fine again.

## Troubleshooting

- **Timeout**: wrong address, SNMP not allowed in on that interface, or credentials the
  agent drops without answering. Many agents answer a wrong password with a timeout, not
  an error.
- **Unknown user name**: the user does not exist on the router.
- **Authentication failure**: `auth_protocol` or `auth_password` differs from the router,
  or (Junos) the passwords were set before the engine id they belong to was committed: set
  them again and commit.
- **Decryption error**: `priv_protocol` or `priv_password` differs from the router.
- **No system group**: the user's view does not include `1.3.6.1.2.1.1`.

## The default-credential probe

lanwatch reads devices with SNMPv3 authPriv only. It speaks SNMPv1 and v2c in exactly one
place: a probe that checks whether a device answers the defaults everybody knows. A device
that answers `public` can be read by anyone on the LAN, and `private` is usually a write
community. The only reliable way to know is to ask: an agent's own community table is no
proof (an APC management card lists `public` as active with SNMPv1 switched off).

What is sent to each device, once per deep scan (weekly) and once when it is new:

- SNMPv1 and v2c: one GET of `sysDescr.0` with `public`, then with `private`. One try,
  two seconds each. These are public defaults, so nothing secret goes over the wire.
- When a community answered: one more GET with it, of `sysName.0` and `sysObjectID.0`.
  With the description, that is enough to tell which device it is (the finding title
  and `lanwatch snmp-audit` show it). Nothing else is read over v1/v2c: that would be
  the polling lanwatch refuses, so read such a device over SNMPv3 instead.
- SNMPv3: one unauthenticated GET with a user name no agent has. An agent that answers
  "unknown user name" is there; that is recorded as a fact on the device, not a finding.
- SNMPv3 defaults: one GET per vendor default login lanwatch knows. The list holds only
  logins a vendor documents (with the source in the code), and is empty for now.

Never a SET, never a walk. Devices in `scan.skip_hosts` are left out. Switch it off with:

```toml
[snmp_audit]
enabled = false
```

Findings:

- `snmp.default-community`: the device answers SNMPv1/v2c on `public` (high) or
  `private` (critical), with the versions that answered. Whether the community can write
  is not tested, since that would mean writing. Resolves once the probe gets no answer.
- `snmp.default-v3-user`: a listed vendor default SNMPv3 login works (high).

What it cannot see: an agent drops a request with a community it does not know, without
a word. So a device with SNMPv1/v2c on and a non-default community looks the same as one
with v1/v2c off. No finding means "does not answer the defaults", not "v1/v2c is off".

Run it now with `sudo lanwatch snmp-audit` (every online device) or
`sudo lanwatch snmp-audit 192.168.1.20` (one device). It needs `snmpget` from the `snmp`
package.
