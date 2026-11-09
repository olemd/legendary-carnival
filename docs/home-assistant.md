# lanwatch and Home Assistant

lanwatch and Home Assistant meet in three places:

1. **Notifications**: findings and the daily digest go to a Home Assistant notify service,
   typically the companion app on your phone. Tapping one opens lanwatch; a button accepts
   the finding or says "yes, that device is mine".
2. **Sensors**: three `sensor.lanwatch_*` entities, updated after every scan round, for
   dashboards and automations.
3. **Firmware**: lanwatch reads the running Home Assistant version off the network and says
   when a newer release is out. Nothing to set up.

Everything below is on the LAN. lanwatch calls Home Assistant's local API with a long-lived
token; Home Assistant calls lanwatch's web UI, if at all, for the "Accept" button.

## 1. Create a token in Home Assistant

Your profile (bottom left) → **Security** → **Long-lived access tokens** → *Create token*.
Name it `lanwatch`. The token is shown once; it goes into lanwatch's config file, which the
Debian package installs readable by root and the service only.

## 2. Configure lanwatch

In `/etc/lanwatch/config.toml`:

```toml
[notify.home_assistant]
enabled = true
url = "http://homeassistant.local:8123"   # or the IP, e.g. "http://192.168.1.5:8123"
token = "eyJhbGciOi..."
service = "notify.mobile_app_my_phone"    # your phone; "notify.notify" sends to everything
publish_sensors = true
lanwatch_url = "http://192.168.1.10:8321" # lanwatch's web UI as your phone reaches it
```

- `service` is the notify service of the device that should get the message. Find the name
  under **Developer tools → Actions**, type `notify.` and pick your phone
  (`notify.mobile_app_<phone name>`). `notify.notify` goes to every notify target.
- `lanwatch_url` makes the notification tappable and adds the buttons (section 4). It is the
  address a phone on your Wi-Fi uses to open lanwatch, so lanwatch has to listen beyond
  localhost, which in turn requires a password:

```toml
[web]
host = "0.0.0.0"
port = 8321
password = "a long password"              # HTTP basic auth, user "lanwatch"
```

Then:

```sh
sudo systemctl restart lanwatch
sudo lanwatch notify --test      # one test message to every enabled channel
```

The phone should buzz within a few seconds. `sudo lanwatch notify` and the *Notifications*
page in the web UI list every delivery, with the error when one failed.

### Which findings are pushed

Findings at or above `notify.min_severity` (default `medium`) are pushed once, when they
open, batched per scan round. The daily digest (`[llm]`, 07:00 by default) is pushed too.
To raise the bar for the phone alone:

```toml
[notify.home_assistant]
min_severity = "high"
```

## 3. Sensors

With `publish_sensors = true` lanwatch writes these entities after every round:

| Entity | State | Attributes |
|---|---|---|
| `sensor.lanwatch_devices_online` | devices that answered the last discovery | |
| `sensor.lanwatch_devices_known` | devices ever seen | |
| `sensor.lanwatch_open_findings` | open findings | `open_critical`, `open_high`, `open_medium`, `open_low`, `open_info`, `last_discovery`, `last_inventory` |

They are set through the states API, so they are not tied to an integration: Home Assistant
keeps them until it restarts, and lanwatch recreates them on the next round (within five
minutes). Do not expect them to survive a Home Assistant restart on their own.

A dashboard card:

```yaml
type: entities
title: Network
entities:
  - entity: sensor.lanwatch_devices_online
    name: Devices online
  - entity: sensor.lanwatch_open_findings
    name: Open findings
  - type: attribute
    entity: sensor.lanwatch_open_findings
    attribute: open_high
    name: of which high
  - type: attribute
    entity: sensor.lanwatch_open_findings
    attribute: last_discovery
    name: Last scan
```

An automation that speaks up when something critical appears, independent of the push
notification:

```yaml
alias: lanwatch critical finding
triggers:
  - trigger: numeric_state
    entity_id: sensor.lanwatch_open_findings
    attribute: open_critical
    above: 0
actions:
  - action: tts.speak
    target:
      entity_id: tts.home_assistant_cloud
    data:
      media_player_entity_id: media_player.kitchen
      message: "lanwatch has a critical finding on the network."
```

## 4. Notification buttons

Every notification carries the full finding as `data.lanwatch` (the same JSON the webhook
channel sends), and a `tag`, so a later message about the same finding replaces the earlier
one on the phone. With `lanwatch_url` set, it also carries:

- a tap target: the device's page in lanwatch when the notification is about one device,
  else the findings list,
- an **Open in lanwatch** button (the app follows the link itself),
- for a single new finding, an **Accept** button, labelled **Yes, that's mine** when the
  finding is a new device.

The Accept button does not reach lanwatch by itself: the companion app turns it into a
`mobile_app_notification_action` event in Home Assistant, with the finding id in the event
data. One `rest_command` and one automation forward it to lanwatch's acknowledge endpoint,
which marks the finding accepted (it stays acknowledged for good, with the note).

`configuration.yaml`:

```yaml
rest_command:
  lanwatch_accept:
    url: "http://192.168.1.10:8321/findings/{{ finding_id }}/ack"
    method: post
    username: lanwatch
    password: !secret lanwatch_web_password
    content_type: "application/x-www-form-urlencoded"
    payload: "accept=true&note={{ note | urlencode }}"
```

`secrets.yaml`:

```yaml
lanwatch_web_password: "the web.password from lanwatch's config"
```

The automation:

```yaml
alias: lanwatch accept from notification
triggers:
  - trigger: event
    event_type: mobile_app_notification_action
    event_data:
      action: LANWATCH_ACCEPT
actions:
  - action: rest_command.lanwatch_accept
    data:
      finding_id: "{{ trigger.event.data.finding_id }}"
      note: >-
        {% if trigger.event.data.rule_id == 'inventory.new-device' %}Mine, accepted from the phone
        {% else %}Accepted from the phone{% endif %}
```

Reload the automations (or restart Home Assistant once for the `rest_command`). The next
new-device notification shows **Yes, that's mine**; pressing it acknowledges the finding
in lanwatch, and the device's page shows the note.

A device that is yours is still a device: name it in lanwatch (its page, or
`lanwatch name <id> "Kitchen tablet"`) so the next finding about it reads well.

## 5. Firmware

The daily firmware check asks the network over mDNS which Home Assistant version is running
and compares it with the current stable release (with `[firmware] online = true`, the
default). Behind it is a `device.firmware-outdated` finding, like for ESPHome, Shelly,
Tasmota, Pi-hole and Jellyfin. Nothing to configure; it needs lanwatch and Home Assistant on
the same network segment, since mDNS does not cross routers.

## Troubleshooting

- **`notify --test` fails with 401**: the token is wrong or was revoked. Create a new one.
- **404 on the notify service**: the service name is not `domain.service`, or the phone is
  not set up in the companion app. Check **Developer tools → Actions**.
- **The phone gets nothing, the log says delivered**: the companion app's notification
  channel may be muted on the phone. Send a test from Home Assistant's own notify UI.
- **Tap does nothing / no buttons**: `lanwatch_url` is unset, or the phone cannot reach it
  (wrong address, or lanwatch still bound to 127.0.0.1).
- **Accept button has no effect**: the `rest_command` failed. Home Assistant's log says
  why; a 401 means the web password in `secrets.yaml` differs from `web.password`, a 403
  means the request carried an `Origin` header, which `rest_command` does not do.
- **Sensors `unavailable` after a Home Assistant restart**: expected until the next lanwatch
  round, within five minutes.
