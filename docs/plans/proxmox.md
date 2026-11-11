# Plan: Proxmox VE integration (future, not started)

Status: idea, 2026-11-11. Split off from `device-links`, where a manual `runs-on` link
kind was dropped: in a cluster a VM moves between hosts, and a fixed link to one host
goes stale on the first migration. Only the hypervisor knows where a VM runs now.

## Why

- Devices with the MAC prefix `BC:24:11` (Proxmox Server Solutions GmbH) are Proxmox
  VMs. lanwatch sees them as ordinary devices and cannot tell which host runs them.
- On the home network: hydra (172.16.123.9) and medusa (172.16.123.17) are the Proxmox
  hosts; several VMs (.27, .30 naga, .31 nue) run on one of them.

## First, without the integration: mark VMs by MAC prefix

Can be done on its own, before (and without) the API integration. Hypervisors give
virtual NICs MACs from their own prefixes, so the address alone says "virtual machine",
as a fact, no guess:

- `BC:24:11` Proxmox, `52:54:00` QEMU/KVM (libvirt), `00:50:56` / `00:0C:29` /
  `00:05:69` VMware, `00:15:5D` Hyper-V, `00:16:3E` Xen, `08:00:27` VirtualBox.
- Show it where the vendor is shown, e.g. "Proxmox (VM)" in the device list's vendor
  column and on the device page, and pass it to the LLM classification as a fact.
- Deterministic and offline: a small prefix table next to the OUI lookup.
- Not which host it runs on; that needs the API below.

## Shape, like the UniFi and airOS integrations

- Opt-in `[proxmox]` table: `url` of any cluster node, a read-only API token
  (`PVEAuditor` role), `verify_tls`. Off by default; nothing changes without it.
- Read each infra round: `GET /cluster/resources` (VMs, containers, nodes, state, which
  node), and each guest's config for its network MACs (`net0: virtio=BC:24:11:...`).
- Match guests to devices by MAC. Store as facts in `attrs.proxmox` (guest name, id,
  node, state, HA state), not as links to confirm: it is the source's own data, not a
  guess, so the rule "suggestions are never applied silently" does not apply.
- Device page: "VM 104 naga on hydra"; the host's page lists its guests. A migration is
  a timeline event.

## What it makes possible

- A VM that stops answering because it was shut down or its node is down is explained,
  as the BMC link does for a powered-off server.
- Rules (deterministic, as always): a node down or out of quorum, a guest that should
  run (`onboot`, HA) but does not, a node behind on updates (if the API exposes it).
- The chat's `get_device` gets the hypervisor view.

## Open questions

- Containers (LXC) share the prefix: same treatment?
- Clusters behind one URL vs. standalone hosts: a list of URLs?
- Whether `runs-on` links come back as derived, read-only links fed by this data, or
  whether `attrs.proxmox` alone is enough.
