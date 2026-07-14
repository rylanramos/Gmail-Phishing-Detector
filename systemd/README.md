# systemd units

Unit files for running this project's scheduled components on a Linux host
(e.g. the container at `/opt/phishing-detector`). These mirror the units
already running live there for the scanner and dashboard
(`phishing-detector.service`/`.timer`, `phishing-dashboard.service`), which
predate this directory and are not yet tracked here — copy them in from a
live host with `systemctl cat <unit>` if you want them version-controlled
too.

## Installing a unit

```
sudo cp systemd/phishing-pihole-correlate.service systemd/phishing-pihole-correlate.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now phishing-pihole-correlate.timer
```

Check it's scheduled and inspect the last run:

```
systemctl status phishing-pihole-correlate.timer
systemctl status phishing-pihole-correlate.service
journalctl -u phishing-pihole-correlate.service -n 50
```

## Units in this directory

- `phishing-pihole-correlate.service` / `.timer` — runs
  [app/correlate_main.py](../app/correlate_main.py) hourly. Requires
  `credentials/pihole_api_password.txt` (or `PIHOLE_API_PASSWORD`) to be
  configured first; see the "Pi-hole correlation" section of the main
  [README](../README.md). Without it, the timer will still fire but each run
  logs a skip reason and exits cleanly rather than doing anything.
