# Plan: UPS over SNMP (branch `snmp-ups`, after `snmp-multi`)

Status: draft, 2026-11-10. Depends on `snmp-multi` (the device list and the reader
registry). First device: APC Smart-UPS 3000 (SMT3000RMI2U, UPS firmware
`08.8 (ID18)`), with an AP9630 card (NMC2, hardware 05, AOS 7.2.2), at 172.16.123.143.
It answers SNMPv3 with SHA + AES-128, user `lanwatch`.

## Reads

**Vendor-neutral: RFC 1628 UPS-MIB (`1.3.6.1.2.1.33`).**
- Identity: `.1.1.1–.1.1.3`. `.1.1.4`, the agent software version, is missing on this
  card.
- Battery: `upsBatteryStatus` (`.1.2.1`), seconds on battery (`.1.2.2`), minutes left
  (`.1.2.3`), charge (`.1.2.4`).
- Power: `upsOutputSource` (`.1.4.1`), load in percent (`.1.4.4.1.5`), input voltage
  (`.1.3.3.1.3`).
- Alarms: `upsAlarmsPresent` and `upsAlarmTable` (`.1.6`).

**APC PowerNet (`1.3.6.1.4.1.318.1.1.1`), when the enterprise is 318.** Walk only these
subtrees, never `318.1.4` (undocumented, "experimental") or the whole tree.
- `upsCommStatus` (`8.1`): 2 means the card has lost the UPS. Then every other value is
  stale.
- `upsBasicOutputStatus` (`4.1.1`): online, on battery, SmartBoost, SmartTrim, bypass.
- `upsAdvInputLineFailCause` (`3.2.5`): the reason for the last transfer to battery.
- Input min and max voltage (`3.2.2/3`); active power W and apparent power VA
  (`4.2.8/9`); energy used (`upsHighPrecOutputEnergyUsage`, `4.3.6`; confirm the unit).
- `upsAdvIdentFirmwareRevision` (`1.2.1`), the UPS firmware.
- `upsAdvBatteryReplaceIndicator` (`2.2.4`); last replacement (`2.1.3`); recommended
  replacement date (`2.2.21`); cartridge (`2.2.19`).
- `upsAdvTestDiagnosticsResults` and `LastDiagnosticsDate` (`7.2.3/4`); the schedule
  (`7.2.1`, 8 = every two weeks since the last test); `upsAdvTestCalibrationDate`.
- `upsAdvConfigLowBatteryRunTime` (`5.2.8`, ticks): the margin before shutdown.

**Date formats differ per field.**
- The card's own dates are `mm/dd/yyyy`: the self-test date, and `mconfigClockDate`
  (`11/10/2026` on 10 Nov).
- The UPS's own dates are `dd.mm.yyyy`: the battery dates and the manufacture date.
- Parse each field with its own format. A date that does not parse is unknown, never
  guessed.

## Rules

All of them auto-resolve unless noted.
- `ups.no-communication`: the card cannot reach the UPS. High. It stops the rules below
  from reporting stale values.
- `ups.on-battery`: on battery. High.
- `ups.battery-low`: status low or depleted, or minutes left below the threshold
  (default 10). Critical when on battery, medium otherwise.
- `ups.battery-replace`: a replace-battery alarm or the APC indicator. Medium.
- `ups.alarm`: other alarms present, with their names. Medium.
- `ups.self-test-stale`: last self-test older than twice the schedule (low), or failed
  (medium).
- `ups.power-event`: an event, closed by ack. "Went on battery at HH:MM for N s, cause
  X". It is caught from `upsSecondsOnBattery` and the cause between rounds.

## Firmware

- The card: `sysDescr` holds `MN:AP9630 … PF:v7.2.2 AF1:v7.2.2`. This goes into
  `attrs.firmware` as product "APC NMC", so `device.firmware-outdated` picks it up.
- Latest: there is no public feed, so the latest version per card family is pinned in
  code. NMC2 is 7.2.2 (2025-09-04), and this card runs it.
  - NMC2 looks past active development; Schneider points to NMC3 (AP9640/41). Add an
    improvement note once an official end-of-support date exists.
- The UPS firmware (`08.8 (ID18)`) is shown only, never flagged. There is no official
  list, and UPS flashes have bricked units.

## Web UI

A UPS gets its own block on its device page, and a tile on the dashboard.
- **Status line:** on mains or on battery (large), the last transfer and its cause,
  and whether the card can reach the UPS.
- **Gauges:** charge %, runtime in minutes against the low-battery margin, and load %
  with W/VA.
- **Graphs** (server-side SVG like the existing sparklines, with no JS library), over
  24 h and 7 d, chosen with a toggle:
  - load W;
  - input voltage, with min and max and the transfer thresholds (207/253 V) drawn
    as lines;
  - runtime;
  - battery temperature.
- **Power events:** a timeline of on-battery periods with duration and cause, taken
  from the finding history.
- **Battery card:** installed, recommended replacement date, cartridge type, last
  self-test and its result, and whether runtime has been calibrated.
- **Firmware:** card and UPS versions, with the latest card version known.
- **Dashboard tile:** state, runtime, load, and a 24 h load sparkline. It is hidden
  when no UPS is known.

Storage: this branch owns migration v12, a generic table `snmp_series(ts, host, metric,
value)` indexed on (host, metric, ts).
- It is pruned with the other round history (`Store.prune`, `rounds_before`).
- Store helpers: `add_snmp_series(host, values, ts)` and
  `snmp_series(host, metric, since)`. A ready patch with tests sits in the scratchpad
  (`series-from-step2.patch`, cut from `snmp-multi`).
- The UPS reader returns its numeric readings, and the collector writes them: one row
  per metric per round. Metrics: `ups.load_w`, `ups.input_v`, `ups.runtime_min`,
  `ups.charge_pct`, `ups.battery_c`.
- About 7 k rows a day per UPS at a 5-minute round.
- The table is generic, so other kinds can use it later. Only this branch may create
  it.

Home Assistant: the same facts as sensors through the existing integration (state,
charge, runtime, load).
