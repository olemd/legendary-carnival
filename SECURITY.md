# Security policy

lanwatch scans a network, stores what it finds, and holds credentials for the devices it
reads (SNMP, UniFi, airOS, Home Assistant). A flaw in it can expose more than lanwatch
itself, so reports are welcome and taken seriously.

## Supported versions

Only the newest release gets security fixes. Fixes are not backported: the fix for a
confirmed problem ships as a new release, through the apt repository and on the
[releases page](https://github.com/olemd/legendary-carnival/releases).

## Reporting a vulnerability

Please do not open a public issue for a security problem.

- **Preferred:** use GitHub's private reporting form:
  [Report a vulnerability](https://github.com/olemd/legendary-carnival/security/advisories/new).
  Only the maintainers can read the report.
- **Or by e-mail:** olemd@glemt.net, with "lanwatch security" in the subject.

It helps to include:

- the lanwatch version (`lanwatch version`) and how it is installed (Debian package,
  bare systemd, rootful or rootless podman);
- what an attacker needs to start with (a place on the LAN, a login on the machine, a
  device lanwatch scans, access to the web UI);
- the steps to reproduce it, and what the attacker ends up with.

Leave out real credentials, and addresses or device names from your network that the
report does not need.

## What to expect

This is a small project maintained in spare time, so there are no guaranteed response
times. The aim is to acknowledge a report within a week, and to tell you whether it is
confirmed and how it will be fixed once that is known. You will be credited in the
release notes unless you would rather not be.

Please give a fix a reasonable time to reach a release before you publish details.

## What counts

Reports about lanwatch itself, for example:

- getting past the web UI's access control, or reaching it from outside the address it
  is bound to;
- making `lanwatch-helper` run something other than its allowlisted scan commands, or
  gaining privileges through the service, the helper or the package's install scripts;
- a device on the network making lanwatch run code, write files or leak its stored
  credentials through a crafted response (SNMP, mDNS, UPnP, HTTP, hostnames);
- credentials or scan data ending up in logs, notifications, or requests to the local
  LLM or to online lookups where the documentation says they do not.

Not in scope: weaknesses lanwatch finds in other devices (that is what it is for), and
problems that need root on the machine lanwatch runs on to begin with. A vulnerability
in a bundled dependency is in scope when it can be reached through lanwatch; otherwise
please report it to that project.
