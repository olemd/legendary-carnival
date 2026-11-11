# Plan: checks on every SNMP target (branch `snmp-checks`, after `snmp-multi`)

Status: draft, 2026-11-10. These are vendor-neutral checks that work on any device read
over SNMP. They use only the target rows from `snmp-multi`: no migration, no reader of
their own beyond one OID.

## Clock skew

- The device's time comes from `HOST-RESOURCES hrSystemDate` (`1.3.6.1.2.1.25.1.2.0`,
  DateAndTime with an optional UTC offset), which the SRX answers. Failing that, from
  the APC card's own clock (`mconfigClockDate` / `mconfigClockTime`,
  `1.3.6.1.4.1.318.2.1.6.1.0` / `.2.0`, in `mm/dd/yyyy` and `hh:mm:ss`, local time
  without an offset).
- It is read as a reader through the `snmp-multi` registry and stored as
  `facts.clock = {device_time, offset_s, read_at}`.
- The offset allows for the read's duration: the midpoint of the request counts.
- Rule `snmp.clock-skew`: more than 2 min off is low, more than 1 h is medium.
  Auto-resolves.
  - The APC clock has no time zone, so it is compared in lanwatch's local zone, and
    only a skew above 2 min that is not a whole number of hours is flagged. A whole hour
    off is reported as "time zone or DST setting", at low severity.
- Measured on 2026-11-10: UPS 11 s behind, SRX in sync. `NTPv4-MIB` did not answer on
  the SRX, so there is no "is NTP synced" check.

## Unreachable target

- Rule `snmp.unreachable`: a configured target whose last 3 reads in a row failed
  (`fails >= 3` in its row), with the last error as evidence. Low; medium for the
  router. Auto-resolves on the next good read.
- A target that never answered at all (`last_ok` is None) says so in the title: "never
  read". That is usually a login or ACL problem, and the evidence points to
  `docs/snmp.md`.

## Tests

- DateAndTime parsing (8 and 11 octets, with and without offset), the APC format,
  the skew thresholds, the whole-hour case.
- Unreachable counting: below 3 no finding, 3 and above a finding, resolving after a
  good read.
