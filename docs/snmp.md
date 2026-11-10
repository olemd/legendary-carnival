# lanwatch and the router over SNMPv3

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

### UniFi gateways

UniFi Network has SNMPv3 with a username and one password, and fixed algorithms: SHA-1
for authentication and AES-128 for encryption. Where to switch it on has moved between
Network versions; Ubiquiti's article "SNMP Monitoring in UniFi Network"
(https://help.ui.com/hc/en-us/articles/33502980942615) has the current place. In
lanwatch, use the one password for both:

```toml
[snmp]
enabled = true
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

In `/etc/lanwatch/config.toml`:

```toml
[snmp]
enabled = true
# host = "192.168.1.1"      # default: this host's default gateway
user = "lanwatch"
auth_protocol = "SHA-256"
auth_password = "..."
priv_protocol = "AES"       # AES-128; Junos has no other AES variant
priv_password = "..."
```

`lanwatch config show` prints `***` for both passwords. lanwatch never puts them on a
command line: each read writes a private snmp.conf in a temporary directory, readable only
by the service, and removes it afterwards.

The package recommends the `snmp` package, which has `snmpbulkwalk`. `apt install
./lanwatch_*.deb` installs it along; `dpkg -i` and `--no-install-recommends` do not, and
then `apt install snmp` does. Without it, `lanwatch snmp` and the log say so.

MIB files are not needed: lanwatch asks for numeric output and knows the few OIDs it reads.
Debian's `snmp-mibs-downloader` (non-free, and it downloads the MIBs from the internet when
installed) only makes `snmpwalk` output readable when you query the router by hand.

## 3. Check it

```
sudo lanwatch snmp
```

prints what the router says it is, how long it has been up and how many ARP entries and
leases it has. After that the infra job reads it every round (`schedule.infra_interval_s`,
15 minutes by default).

To test the user without lanwatch, from the same host:

```
snmpget -v3 -l authPriv -u lanwatch -a SHA-256 -A AUTH-PASSWORD -x AES -X PRIV-PASSWORD \
  192.168.1.1 1.3.6.1.2.1.1.5.0
```

(this puts the passwords in your shell history and the process list, so only for a test).

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
