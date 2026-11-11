# A UPS over SNMPv3

A UPS with a network management card is read like any other SNMP device: give the card
its own `[snmp.devices.<name>]` table (see [snmp.md](snmp.md)). lanwatch recognises it
by itself, with no extra setting:

- an APC card (enterprise 318 in `sysObjectID`) is read at once;
- any other device is asked whether it answers the standard UPS-MIB (`upsIdent`, a
  handful of values), and read as a UPS only if it does.

Read only, SNMPv3 authPriv only, like everything lanwatch reads over SNMP.

## Setting up an APC card (NMC2 AP9630/31, NMC3 AP9640/41)

In the card's web UI:

1. **Configuration → Network → SNMPv3 → User Profiles**: pick a profile, set the user
   name (`lanwatch`), an authentication passphrase with **SHA** and a privacy
   passphrase with **AES**. NMC2 offers SHA-1 and AES-128 at most; lanwatch allows both
   (`auth_protocol = "SHA"`, `priv_protocol = "AES"`).
2. **Configuration → Network → SNMPv3 → Access Control**: enable access for that user,
   from lanwatch's address.
3. **Configuration → Network → SNMPv1 → Access**: switch SNMPv1 **off**, unless something
   else needs it. Its communities go over the network in clear text, and `private` is a
   write community.
4. While there: **Configuration → Network → Console → Access**: telnet off, SSH on; and
   FTP off unless you upload firmware that way. lanwatch reports telnet and FTP as
   findings.

Then, in `/etc/lanwatch/config.toml`:

```toml
[snmp.devices.ups]
host = "192.168.1.20"
user = "lanwatch"
auth_protocol = "SHA"
auth_password = "..."
priv_password = "..."
```

`sudo lanwatch snmp` reads it once and prints what it found.

## What lanwatch reads

From the standard UPS-MIB (RFC 1628), on any UPS: on mains or on battery, battery status,
charge, minutes left, battery temperature, input voltage, load, the alarm table, and the
voltages at which the UPS switches to battery.

From APC's PowerNet-MIB, on an APC card: whether the card can still talk to the UPS, a
finer output state (SmartBoost, SmartTrim, bypass), why the UPS last went to battery,
power in W and VA, the input voltage range, the UPS's own firmware, the battery's
cartridge, last replacement and recommended replacement date, and the self-test result,
date and schedule. Only six named subtrees are walked, never the whole tree. Serial
numbers are not stored.

The card's own firmware (from its `sysDescr`) goes to the device's firmware line, and is
compared with the newest release lanwatch knows for that card family. Schneider publishes
no machine-readable release list, so that version is pinned by hand (NMC2: 7.2.2, checked
2026-11-10). The UPS's own firmware is shown only: there is no official list to compare it
with, and flashing UPS firmware can brick a unit.

## Findings

| Rule | When | Severity |
|---|---|---|
| `ups.no-communication` | the card answers but has lost contact with the UPS; the rules below then stay quiet | high |
| `ups.on-battery` | running on battery | high |
| `ups.battery-low` | battery low or depleted, or under 10 minutes left | medium; critical while on battery |
| `ups.battery-replace` | the UPS says replace, a battery-bad alarm, or the recommended date has passed | medium |
| `ups.alarm` | any other alarm in the UPS-MIB alarm table | medium |
| `ups.self-test-stale` | the last self-test failed (medium), or it is older than twice the schedule (low) | low / medium |
| `ups.power-event` | the UPS went on battery; stays after the power is back until acknowledged | medium |

All but `ups.power-event` resolve by themselves. An outage is seen when an infra round
(every 15 minutes by default) reads the UPS during it, so a shorter one can be missed.
If the card itself cannot be read, its last values are not used for findings.

## Web

The UPS's device page has a UPS section: state, gauges for charge, runtime and load,
graphs over 24 hours or 7 days (load, input voltage with the transfer thresholds,
runtime, battery temperature), battery, firmware and power events. The dashboard has a
UPS tile when there is one. The readings for the graphs are kept like the other round
history (`[store] keep_days`).

## Not read

- Energy used (`upsHighPrecOutputEnergyUsage`): the MIB says hundredths of kWh, which
  gives an implausible figure on the one unit tested; left out until the unit is
  confirmed.
- PowerNet's undocumented "experimental" branch (`318.1.4`), outlet groups, and the
  card's own settings.
- Nothing is ever written: no self-test, no shutdown, no settings.
