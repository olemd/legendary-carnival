# Plan: SNMP audit probe (branch `snmp-audit`, from `main`, independent of the others)

Status: built on branch `snmp-audit`, 2026-11-11 (see "Built" at the end).

## Why

Polling stays SNMPv3 authPriv only. But a device that answers SNMPv1/v2c on `public`
or `private`, or SNMPv3 with a vendor's default user and passphrase, is a finding in its
own right: anyone on the LAN can read it, and with a write community, change it. The
only reliable way to know is to try. This works the same way as the telnet and FTP
checks: lanwatch reports configurations that are widely considered unsafe, on a network
you administer.

## Not a reliable signal: the community table read over v3

The APC card lists `public` and `private` as active in `SNMP-COMMUNITY-MIB` while
SNMPv1 is switched off in its web UI. The SRX does not expose the table at all. So the
table is never used as evidence. Only a real answer counts.

## What is sent

- **v1 and v2c:** one `GET sysDescr.0`, with `public` and then `private`. No walk and
  no SET, ever.
  - A read that works with `private` is reported as "default write community answers
    for reading". Whether it can write is not tested, because testing that means
    writing.
- **v3:** an engine-discovery request (an empty, unauthenticated GET; the agent answers
  with a report). This shows that an SNMPv3 agent is present and gives its engine ID,
  which often contains the vendor and MAC address. Inventory facts only.
- **v3 defaults:** a short list of documented vendor default users and passphrases,
  each tried with one `GET sysDescr.0`.
  - Every entry needs a cited source. The list starts with APC NMC only if its defaults
    can be confirmed from APC documentation.
  - No guessing beyond that list.

## Detecting SNMPv1/v2c in general

An agent drops a request with an unknown community silently. So "v1/v2c enabled with a
non-default community" cannot be seen from outside. The finding therefore says what was
tested ("v2c answers on `public`"), and the docs say plainly that silence does not prove
v1/v2c is off.

## Rules

| id | when | severity |
|---|---|---|
| `snmp.default-community` | v1/v2c answers on `public` | high |
| | v1/v2c answers on `private` | critical |
| `snmp.legacy-version` | v1/v2c answers at all (always together with the one above, since only defaults are tried) | folded into the evidence of the rule above; no separate finding |
| `snmp.default-v3-user` | a listed vendor default works | high |

The default-community rule auto-resolves once the probe stops getting an answer.

## Which devices, how often

**Every online device, whether or not a scan found an SNMP port.** "SNMP port open"
cannot be known without asking:
- SNMP runs over UDP, and an agent says nothing to a request it does not accept.
- The hourly light scan is TCP only.
- The weekly UDP scan reports 161 as `open|filtered` for any device that stays silent.
  It marks it `open` only when the agent answered nmap's own `public` probe, which is
  exactly this test.

So the probe is the port check itself. Targets:
- Every device online in the current round.
- All configured SNMP targets, even if they are offline right now; they are probed
  when they come back.
- The probe runs on the deep-scan schedule (weekly), and once for each new device.
- Switch: `[snmp_audit] enabled = true` (default on), and `skip_hosts` is respected.
- Load: two to four UDP packets per device. This is harmless, and the same as the
  `public` probe nmap's UDP scan already sends to port 161.

## Docs and PLAN

- `docs/snmp.md`: state the line clearly. lanwatch polls with v3 only. It speaks v1/v2c
  only to test the well-known defaults, once per probe, and never with real credentials.
- `PLAN.md` decisions: add this as a dated decision.

## Verified so far

- UPS card: SNMPv1 is disabled in the UI (2026-11-10), but its community table still
  says active. That is the reason this probe exists, rather than the table check.

## Built

Where the branch differs from the plan above:

- **The v3 presence check** is an unauthenticated GET with a user name no agent has,
  not an engine-discovery request: net-snmp's `snmpget` does that discovery itself, and
  the answer "unknown user name" is what tells that an agent is there. The engine ID
  is not kept.
- **`V3_DEFAULTS` is empty.** No vendor default could be confirmed from vendor
  documentation, so `snmp.default-v3-user` has nothing to try yet.
- **Identity:** when a community answers, one more GET with it reads `sysName.0` and
  `sysObjectID.0`, so the finding and `lanwatch snmp-audit` say which device it is. Nothing
  else is read over v1/v2c.
- **Targets:** the devices of the deep scan (weekly) and of each new-device scan.
  Configured SNMP devices that are offline are not probed (the branch does not depend
  on `snmp-multi`); they are probed with the next deep scan once online.
- First run on the home network (2026-11-11): `public` answered on an HP printer and on
  two iLO 4 cards; the SRX and the UPS did not answer any default.
