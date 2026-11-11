# Plan: several SNMP devices (branch `snmp-multi`)

Status: done, 2026-11-11 (pull request open). This branch is plumbing only, with no new findings and
no device-specific reads. The features each have their own branch:

| Branch | Plan | Depends on |
|---|---|---|
| `snmp-multi` | this file | - |
| `snmp-checks` | `snmp-checks.md`: clock skew, unreachable target | `snmp-multi` |
| `snmp-audit` | `snmp-audit.md`: default-credential probe | nothing |
| `snmp-ups` | `snmp-ups.md`: UPS reads, rules, web UI and graphs | `snmp-multi` |
| `snmp-junos` | `snmp-junos.md`: deeper Junos reads (bonus) | `snmp-multi` |

## Why

0.8.0 reads one device over SNMPv3: the router. Other gear answers SNMPv3 too: the APC
UPS card, and at work an SRX1500 and an EX4600. This branch lets lanwatch read any
number of devices, and gives the feature branches places to plug in, so that they
neither depend on each other nor conflict.

Policy unchanged: polling is SNMPv3 authPriv only, read only, and MD5/DES are refused.

## Scope

1. **Config** (done, `7d830e5`).
   - One table per device, named by the user: `[snmp.devices.<name>]` with `host`,
     `user`, the protocols, passwords, `timeout_s` and `enabled`. Nothing is shared
     between devices: a login belongs to the device it was made on. `router = true`
     marks the router (at most one), whose ARP table and leases are read too; it alone
     may leave out `host` (the default gateway).
   - 0.8.0's form (the router's login straight under `[snmp]`) is still read, as the
     device `router`.
   - Each entry is validated. `config show` now redacts secrets inside lists of tables
     too.
2. **Reading and state** (done, `682659d`).
   - Every target is read in the infra round; each gets the system group, and the
     router also gets its ARP table and leases, as before.
   - One infra row per target (kind `snmp-target`, keyed by host): system, last ok,
     last error, failures in a row.
   - `attrs.snmp` goes on the device holding the address.
   - Migration v11 moves the router's 0.8.0 meta keys into its row.
   - `lanwatch snmp` lists every target.
3. **Hook points for the feature branches** (done):
   - **A reader registry** (`collectors/snmp_kinds.py`): a list of readers, each with
     `matches(system) -> bool` and `read(client) -> facts`. It is empty here. For each
     target, the collector runs the readers that match and stores the result in the
     target row under `facts[<reader name>]`. A reader that fails is logged and
     skipped, and the system read still counts.
   - **Rules from every module**: `all_rules()` collects `RULES` from every module in
     `lanwatch.rules`, sorted by module name. A new rule file then needs no edit to a
     shared list.
4. **Web.**
   - The infra page gets a table of targets: name, host, role, vendor, last read,
     error.
   - The status tile counts the devices next to the router.
   - The device page shows `attrs.snmp`.
5. **Docs.** `docs/snmp.md` covers several devices and the fallback of the login fields;
   the README config example is updated.

Not here: the clock check and the unreachable rule (`snmp-checks`); readings over time
and graphs (`snmp-ups`); any UPS or Junos read.

## Merge order and conflicts

- `snmp-multi` first. Then `snmp-checks`, `snmp-ups` and `snmp-junos` in any order.
  `snmp-audit` can go any time, even before `snmp-multi`.
- **Migrations:** `snmp-multi` adds v11. `snmp-ups` adds v12 (`snmp_series`). No other
  branch adds one. If a second branch ever needs one, it must be rebased on whatever
  merged first.
- **How the order is enforced:** stacked pull requests. `snmp-checks`, `snmp-ups` and
  `snmp-junos` branch from `snmp-multi`, and their PRs target `snmp-multi`, not `main`.
  Until `snmp-multi` merges, they cannot reach `main`. Once it merges and the
  `snmp-multi` branch is deleted, GitHub retargets them to `main` by itself.
  "Automatically delete head branches" is off in this repo, so either delete the branch
  by hand or change each PR's base. Without `snmp-multi`, those branches would not build,
  so CI also catches a wrong order.
- Version bumps are left to the release commit, as with 0.8.0.
- **Docs per branch.** Every branch documents its own feature, each at its own anchor,
  so that the doc edits do not touch the same lines:

  | Branch | `docs/snmp.md` | README feature list | Other |
  |---|---|---|---|
  | `snmp-multi` | "More devices than the router" | the SNMP bullet; devices are mentioned in it | `deploy/config.example.toml` example, `PLAN.md` §9 status |
  | `snmp-checks` | "Checks on every device", before "Troubleshooting" | its own bullet before "MAC vendors" | - |
  | `snmp-ups` | one link line under "More devices" | a "UPS" bullet before "Latency" | `docs/ups.md` |
  | `snmp-junos` | "Junos extras", after "### Junos (SRX, EX, MX)" in section 1 | a "Junos extras" bullet before "Router over SNMP" | - |
  | `snmp-audit` | "The default-credential probe", at the end | its bullet between "Router over SNMP" and "Internet exposure" | `PLAN.md` §11 decision, `[snmp_audit]` in the example config |

  - The README rule count ("41 deterministic rules") is updated only in the release
    commit, from `all_rules()`, never in a feature branch.
  - Each branch inserts into its own gap between README bullets, so the README edits
    merge cleanly in any order.
- What remains shared is text only: the README rule count and the config example in
  `docs/snmp.md`. Conflicts there are trivial.

## Steps

1. ~~Config model and tests.~~
2. ~~Reading every target, state per host, v11.~~
3. ~~Reader registry and the rule module scan, with tests. The rule list must stay the
   same: compare the ids before and after.~~
4. ~~Web: targets table, status tile, device facts.~~
5. ~~Docs. Then ruff, mypy, the full suite and the PR.~~
6. ~~Locally: migrate `config.toml` (the router and the UPS as `[snmp.devices.<name>]`
   tables) and build the `.deb`.~~ Read live against an SRX300 and an APC AP9630.
