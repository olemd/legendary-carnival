# lanwatch and Ubiquiti airMAX radios (airOS)

Point-to-point links built from airMAX radios (NanoStation, LiteBeam, PowerBeam, Rocket,
Bullet and their kin) are easy to forget once they work, and they degrade quietly: a
neighbour's network on the same channel, a tree that grew, a mount that moved. lanwatch
can read what each radio knows about itself and its link:

- the radio: model, airOS version (and whether a newer one exists), uptime, AP or station, bridge or router, frequency and
  channel width, the speed of its Ethernet port;
- the link, from both ends: signal and noise, CCQ (the share of frames that got through
  the first time), airMAX quality and capacity, the rates in each direction, and what the
  far end reports about itself.

Everything is read-only, over HTTPS, on the LAN: lanwatch logs in, reads `status.cgi` and
`sta.cgi`, and logs out.

airOS has no SNMPv3 (airOS 6 answers SNMPv1 only), so this is not done over SNMP.

## 1. A read-only account on each radio

On the radio's web UI: **System → System Accounts → Read-Only Account: Enable**, give it
a name (for example `lanwatch`) and a password, **Change**, then **Apply** in the banner
at the top. Without Apply the radio keeps running its old configuration.

Use the same name and password on every radio lanwatch should read. The read-only account
cannot change anything; never give lanwatch the administrator account.

## 2. Configure lanwatch

In `/etc/lanwatch/config.toml`:

```toml
[airos]
enabled = true
hosts = ["192.168.1.20", "192.168.1.21"]
username = "lanwatch"
password = "..."
```

`lanwatch config show` prints `***` for the password.

## 3. Check it

```
sudo lanwatch airos
```

prints each radio, its link and, the first time, the fingerprint of the certificate it
pinned (section 4). After that the infra job reads the radios every round
(`schedule.infra_interval_s`, 15 minutes by default).

## 4. Two safeguards

**One login attempt.** airOS 6.3.14 and later lock an account after three failed logins.
When a radio does not clearly accept the login, lanwatch stops: it remembers that this
username and password failed on that radio (a salted hash, not the password) and does not
try them there again. A changed password in the config is tried on the next round. Any
reply to the login other than the expected redirect counts as a failure, so an unfamiliar
firmware can never use up the attempts.

When the fault was on the radio (the account not enabled, or not applied) and the config
was right all along, fix the radio and then tell lanwatch to try once more:

```
sudo lanwatch airos --retry-login 192.168.1.20
```

**Certificate pinning.** The radios serve a self-signed certificate, which nothing can
vouch for. lanwatch keeps the certificate it sees the first time and from then on lets
TLS accept only that exact certificate, before the password is sent. A radio that
presents another one is not read: either it was reset or replaced, or something is
between lanwatch and the radio. Check which, then:

```
sudo lanwatch airos --accept-cert 192.168.1.20
```

pins what the radio presents now. airOS certificates have 1024-bit RSA keys, which
OpenSSL 3 refuses by default; lanwatch lowers the security level for that one pinned
certificate only. The key size is the radio's weakness, not a lanwatch setting.

## Findings

| Rule | When |
|---|---|
| `airos.link-down` (medium) | the radio answers but is linked with no other radio, two reads in a row |
| `airos.link-poor` (low) | CCQ below 60% for an hour: many frames are sent again |
| `airos.link-degraded` (medium) | signal 6 dB or CCQ 20 points below the link's own normal, two reads in a row |
| `airos.channel-overlap` (low) | a 2.4 GHz link partly on top of Wi-Fi channels 1, 6 or 11, or on the channel of your own access points |
| `airos.certificate-changed` (high) | the radio presents another certificate than the pinned one |
| `airos.login-rejected` (medium) | the radio rejected the read-only login; it is no longer read |
| `device.firmware-outdated` (low) | the radio runs an older airOS than Ubiquiti's newest release for its firmware family (XM, XW, XC, WA) |

The newest release is asked of Ubiquiti's firmware update service
(`fw-update.ui.com`) once a day by the firmware job, like the other vendor lookups, and
only with `[firmware] online = true`. The request names the firmware family, nothing about
your radios.

A point-to-point link is reported once, under the pair of radios, with the worse end's
figures. The link's normal is learned from the link itself: lanwatch watches it for half
a day before judging it, so a link that was always weak is not reported as degraded (but
may be as poor), and one that got worse is. A link that drops keeps its normal for about
a week, so one that comes back weaker is reported too. With `[unifi]` enabled, the channel advice
names your own access points in the way and suggests the one of channels 1, 6 and 11
they use least.

## Troubleshooting

- **login not accepted**: wrong username or password, or the read-only account is not
  enabled (or not applied) on that radio. lanwatch will not try again until the password
  or username in the config changes.
- **another TLS certificate**: see section 4.
- **no TLS connection**: wrong address, the radio is down, or its web server has HTTPS
  turned off (on airOS 6 under Services → Web Server).
