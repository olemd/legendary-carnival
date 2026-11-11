# Plan: devices that belong together (branch `device-links`, from `main`)

Status 2026-11-11: part B built on this branch, from `main` only (no dependency on the
open SNMP PRs). Done: steps 2–5 below (links in findings' evidence only for the
watched-offline rule). `powered-by` and `uplink` exist as manual link kinds.

Tested on the home network with a local build: the three iLOs are recognised from their
service banners, and all three name-match suggestions appear (hydra-ilo → hydra,
medusa-ilo → medusa, imp-ilo → imp). That needed hostnames, which no device had: step 1
found that `scan.resolve_hostnames` only applied to the ping backend. Fixed separately
in PR #17 (`fix-resolve-hostnames`); without it, installs that discover with arp-scan or
nmap get suggestions only for devices someone has named.

BMC recognition also reads `attrs.snmp_audit` (sysName, sysDescr, sysObjectID) when PR
#15 has put it there, without importing anything from that branch.

Not in this branch, decided 2026-11-11:
- Part A (one device at several addresses).
- UniFi uplink suggestions and the topology page (step 6).
- `powered-by` findings, after `snmp-ups` (step 7).
- A `runs-on` kind for VMs: a VM in a cluster moves between hosts, and only the
  hypervisor knows where it runs. Belongs to a Proxmox integration
  ([proxmox.md](proxmox.md)).

## Why

The SNMP audit (PR #15) found `public` answering on two iLO 4 cards:

| Address | sysName | What |
|---|---|---|
| 172.16.123.20 | hydra.nottseter.no | iLO 4, firmware 2.82 (Feb 2023) |
| 172.16.123.21 | medusa.nottseter.no | iLO 4, firmware 2.82 (Feb 2023) |
| 172.16.123.19 | (HP, SNMPv3 agent, no default community) | possibly a third iLO |

Each iLO is the management card of a server (hydra, medusa) that lanwatch also sees as
its own device. lanwatch has no way to say that these two belong together, and no good
way to say that one device sits at several addresses.

## What exists today

- **Identity:** a device is keyed by MAC, else `ip:<address>` (`Device.key` in
  `models.py`). The `devices` table has one `ip` column.
- **Merge** (migration v7, `device_aliases`; `Store.merge_devices`; button on the device
  page, `POST /devices/{id}/merge`, candidates with the same hostname first):
  - Folds `other` into `keep`. `other`'s key becomes an alias, so later sightings of it
    count as `keep`.
  - History (sightings) moves over. `other`'s services and findings are dropped,
    because the next scans produce them again under `keep`.
  - Built for phones that change their private MAC, where that is right.
- **A MAC at two addresses:** `record_hosts` updates `devices.ip` to whatever this
  sighting says, and logs `device.ip-changed`. `sightings` has one row per device per
  round. A device that answers at two addresses in the same round (a router with the
  same MAC on several VLAN interfaces, a server with two IPs on one NIC) therefore
  flips between them and logs an IP change each time. **Check whether that happens
  here** (the SRX's irb units, any multi-homed server) before designing around it.
- **Topology:** only UniFi's own devices, from the UniFi API's `uplink` /
  `uplinkDeviceId` (`collectors/unifi.py`, `web/topology.py`).
- **SNMP (open PRs):** `snmp-target` rows per device, the router's ARP table
  (`router-arp`), `attrs.router` (interface, lease). `snmp-junos` plan: an EX4600's
  BRIDGE-MIB / Q-BRIDGE-MIB forwarding table would give MAC → switch port, and LLDP
  neighbours; neither is built.

## Two different needs

### A. One device, several addresses or MACs

A router with interfaces on several networks, a server with two NICs, a NAS with
bonded links. It is one device: one name, one set of findings.

- Merge already makes it one device, but loses information: only one address is shown,
  and the other address's services are dropped (and come back only if that address is
  scanned under `keep`, which it is not, since scans go by `devices.ip`).
- Wanted: a merged device keeps every address it is seen at, with a last-seen per
  address; the device page shows "also at …"; the services scan covers every address.
- Probably needs a `device_addresses(device_id, ip, mac, last_seen)` table, with
  `devices.ip` staying the primary address for display and scans. Big change: many
  places read `devices.ip`. Decide whether this is in scope for this branch or later.

### B. Two devices that belong together

Different devices with their own services and findings, related in a known way. They
must **not** be merged: the iLO answers when the server is off, has its own firmware,
web UI and findings.

- A link table: `device_links(a_id, b_id, kind, source, created, confirmed)`.
- Kinds to start with:
  - `manages`: iLO / iDRAC / IPMI BMC → the server it manages.
  - `powered-by`: device → UPS. Depends on `snmp-ups` (PR #13) being merged; do this
    step after it.
  - `uplink`: device → switch or access point it hangs off.
- `source`: `manual`, or the hint that suggested it (`name-match`, `unifi`, `lldp`, …).
- Deleting a device deletes its links. Merging moves them to `keep`.

## Where links come from

1. **By hand first**, from the device page, the way merge works: pick the other device
   and the kind.
2. **Suggestions that the user confirms with one click. Never applied silently**: a
   wrong link is worse than none.
   - **BMC name → host name.** These iLOs report the server's FQDN as sysName
     (`hydra.nottseter.no`). Match against the hostname/DNS name of other devices
     (`hydra`). Also the usual patterns: `hydra-ilo`, `ilo-hydra`, `hydra-ipmi`.
     Where the iLO's name comes from: the audit's sysName (v1/v2c, until fixed), or
     SNMPv3 once the iLO is a `[snmp.devices.<name>]` table, or its HTTPS certificate
     / web title from the service scan.
   - **Recognising a BMC:** sysDescr "Integrated Lights-Out", sysObjectID under
     `1.3.6.1.4.1.232.9` (HPE Insight Management), HTTP title or cert, vendor
     Hewlett Packard Enterprise; iDRAC and Supermicro IPMI similarly. Could also feed
     `kind`.
   - **UniFi uplinks:** the integration already knows which switch or AP each client
     and device hangs off.
   - **Later:** a switch's forwarding table or LLDP over SNMPv3 (`snmp-junos` plan,
     EX4600), and iLO host-NIC MACs (Redfish `Systems/1/EthernetInterfaces`, needs
     credentials; probably out of scope).

## What links make possible

- The device page shows its partners: "managed by iLO at 172.16.123.20", "manages
  hydra", "powered by ups", "uplink: switch-x port 12".
- **Server gone but its BMC answers:** report the server as "powered off (its iLO
  answers)" rather than gone or offline. Affects the watch/absence findings.
- **UPS on battery** (with `snmp-ups`): list the devices it powers in the finding.
- **Findings on a BMC** (default community, old firmware, telnet) mention which server
  they put at risk: a BMC controls power, console and virtual media of its server.
- Topology page: draw manual and suggested links next to UniFi's.

## Open questions

- Scope: B only, or A as well? A is the bigger change (every reader of `devices.ip`).
- Should a confirmed `manages` link change the BMC's kind (a "management card" kind)
  or only show the relation?
- Migration number: `main` is at v10, `snmp-multi` adds v11, `snmp-ups` v12. This
  branch adds v11 too; whichever merges second renumbers (a one-line conflict at the end
  of `MIGRATIONS`). The links migration uses `IF NOT EXISTS`, so it is harmless if a
  database already ran it under another number.
- The chat tools (`llm/tools.py`): expose links in `get_device`?

## Steps (draft)

1. Check how the SRX and the servers actually show up today (several addresses per
   MAC? IP-change events?), to settle scope A.
2. `device_links` table, store methods, tests (merge and forget move/delete links).
3. Device page: show links, add/remove by hand.
4. BMC recognition and name-match suggestions, confirm/dismiss on the device page.
5. "Powered off, BMC answers" in the absence logic; links in findings' evidence.
6. UniFi uplinks as suggestions; topology page.
7. After `snmp-ups` merges: `powered-by` and the UPS on-battery finding listing what it
   powers.
8. Docs: README bullet, `docs/` page or section, PLAN.md.
