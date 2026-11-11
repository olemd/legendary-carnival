# Plan: Junos over SNMP in depth (branch `snmp-junos`, after `snmp-multi`)

Status: built on branch `snmp-junos` for the SRX300, 2026-11-11. The SRX1500 and EX4600
recordings from work are still to do (see Steps).

## Ground rule: bonus, never required

lanwatch must stay fully useful with no Juniper gear and no extra setup. Nothing here is
required:
- The reads run only when a target's `sysObjectID` is Juniper (enterprise 2636). There
  is no new config key, and no new step in `docs/snmp.md` beyond "it reads more on Junos".
- A missing or empty table is normal and means "not reported". It is never an error,
  never a finding, and never a log line above debug.
- No rule may need a change on the router to work. Policy hit counts, which need
  `count`, are shown when present and otherwise skipped quietly. The docs mention it as
  an option, not a step.
- No migration and no graphs: facts in the target row only. If graphs are wanted later,
  they use `snmp_series` from `snmp-ups` in a follow-up, after both have merged.
- Everything sits in its own module, `collectors/snmp_junos.py` plus
  `rules/junos.py`, registered through the seams from `snmp-multi`. Removing those two
  files would remove the feature cleanly.
- The vendor-neutral rule `net.route-to-down-interface` (IP-FORWARD-MIB) belongs in
  `snmp-checks` or a small branch of its own, since it is not Junos-specific.

## Target devices

- Home: SRX300, Junos 22.4R3-S2.
- Later, at work: SRX1500 (chassis cluster possible) and EX4600 (switch, virtual
  chassis possible).
- Nothing may assume the SRX300. Features are detected from `jnxBoxDescr` and from which
  tables answer. Each family's reads are optional, and fixtures are recorded per model.

## What the SRX300 answered (whole `1.3.6.1.4.1.2636` walk, 16,656 values in 42 s)

The walk is far too slow to run every round. Read named subtrees only, and the slow
tables less often than every round.

Useful and filled:

| Area | Objects | Use |
|---|---|---|
| Chassis alarms | `jnxRedAlarmState`/`jnxYellowAlarmState` + count + last change | Rule `junos.chassis-alarm` (red: high, yellow: medium). Both are 2 = off on the SRX300. |
| Health | `jnxOperatingCPU/Memory/Temp/Buffer` per component, `jnxFruState/Temp`, `jnxHrStoragePercentUsed`, `jnxBoxKernelMemoryUsedPercent` | Facts. Rules for storage > 90 %, a FRU not online, and sustained high temperature. |
| Config changes | `jnxCmCfgChgLatest*`, `jnxCmCfgChgEvent*` (16-entry ring: time, user, source) | Event finding "config changed by X at T" (info; ack closes it). Detect new entries by index and date. |
| Rescue config | `jnxCmRescueChg*` (state, user, date) | Improvement finding when there is no rescue config. |
| Sessions | `jnxJsNodeCurrentTotalSession` / `Max…` (285 / 65536), creation rate | Rule `junos.session-table-full` (> 80 %). |
| Screens | `jnxJsScreenMon*` per zone: syn flood, port scan, IP sweep, land, ... | Facts per zone, plus a finding on a sudden rise between rounds. |
| DHCP server | `jnxJdhcpLocalServer*` counters; DHCPDECLINE = 111 | Rule `dhcp.declines-rising`: declines growing means an address conflict in the pool (SRX backlog item 8). |
| MAC history | `jnxL2aldHistMacChangedMsg/Timestamp` (256-entry ring) | Which MAC was learned or removed on which port, and when. A second view for presence. Probably richer on the EX. |
| Interfaces | `ifJnxIn/Out*` errors, CRC, `ifJnxCarrierTrans` | Rule for a flapping link (carrier transitions growing), and for interface errors rising. |
| Optics | `jnxDom*` Rx/Tx power, alarms | Rule for optic alarms or warnings. Matters most on SRX1500/EX4600. |
| L2 protection | `jnxL2cpBpduProtect*`, `jnxL2cpLoop*`, `jnxDot1dStp*Protect*` | Rule for a port blocked by BPDU or loop protection. Mainly EX. |
| Licences | `jnxLicenseFeature*` | Rule for a licence expiring or exceeded. The SRX300 has two, both unused. |

Present but not useful here:
- `jnxSubscriber*` duplicates the DHCP bindings.
- `jnxCos*` (5000+ values) is queue statistics, too heavy for the gain.
- `jnxMIMst*`, `mpls*` and `jnxLsysSp*` show mostly defaults.

Tried and not usable:
- **Routes into dead tunnels.** `jnxIpCidrRouteTunnelName` is empty for all 41 routes,
  and the IPsec flow MIBs do not answer, since no IKE is configured. Use the standard
  route instead: `IP-FORWARD-MIB inetCidrRouteIfIndex` pointing at an interface that
  is down (`ifOperStatus`). That gives rule `net.route-to-down-interface`, which works
  on any router. It catches the dead `st0.335/336` routes (SRX backlog item 3). Being
  vendor-neutral, it is not part of this branch (see the ground rule above).
- **Policy hit counts.** `jnxJsPolicy*` has name, zones and action for the 8 policies,
  but no counters, because counting needs `count` in each policy. "Policy never hit"
  therefore needs a config change on the router. Document it, and read the counters
  when they are there.
- `NTPv4-MIB` and `SNMP-COMMUNITY-MIB`: no answer.

## Expected on the work devices (to verify with recordings from there)

- **SRX1500:** `jnxJsClusterMonitoring*` and `JUNIPER-CHASSIS-HIGH-AVAILABILITY` for
  cluster state (node down, failover), and SPU monitoring per SPU.
- **EX4600:** `BRIDGE-MIB`/`Q-BRIDGE-MIB` forwarding table (MAC to port per VLAN),
  which shows which switch port each device sits on. That is the biggest gain for
  lanwatch's inventory. Also `jnxVirtualChassis*` (member down), `POWER-ETHERNET-MIB` (PoE
  budget), LLDP neighbours (the IEEE LLDP-MIB is not in the downloader set; get it from
  netdisco-mibs), and `ENTITY-SENSOR`.

## Steps

1. Record the fixtures, with serials removed: ~~SRX300 now~~ (`tests/fixtures/snmp-junos.txt`),
   SRX1500 and EX4600 from work (still to do).
2. Split the reads into fast (every round) and slow (hourly) subtrees. Not needed for
   now: the reader walks 13 named subtrees (about 470 values on the SRX300), which is
   fast enough every round. Revisit with the EX4600's recording.
3. ~~Rules one by one, each with tests against the fixtures.~~ Done:
   - `junos.chassis-alarm`, `junos.storage-full`, `junos.fru-not-online`,
     `junos.session-table-full`, `junos.config-changed`, `junos.no-rescue-config`,
     `dhcp.declines-rising`.
   - Left out: `junos.licence-expiring`. The licence feature table has no dates, and
     the install table with `jnxLicenseEndDate` is empty on the SRX300, so there is
     nothing to test against. Add it once a device with term licences is recorded.
   - Screens are facts only. There is no "sudden rise" rule yet: a threshold needs
     real data from a flood.
4. ~~Device page: a Junos block with health, alarms, sessions and config changes.~~
