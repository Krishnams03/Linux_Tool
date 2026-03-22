# LySec - Linux Forensics Monitoring Daemon

> Detect - Log - Alert - Correlate (No Prevention)

LySec is a Linux daemon that continuously monitors host activity and writes
forensic-grade, tamper-evident logs for post-incident investigation and
timeline reconstruction.

LySec is intentionally passive: it detects and records events, but does not block,
kill, or prevent activity.

## Architecture

```
┌──────────────────────────────────────────────────────────────────┐
│  lysecd (daemon)                                                 │
│                                                                  │
│  USB | Login | Network | Process | Filesystem monitors           │
│                            │                                     │
│                        Alert Engine                              │
│                            │                                     │
│               JSON logs | syslog | email | webhook               │
└──────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│  lysec (CLI) and lysec-gui (desktop dashboard)                  │
└──────────────────────────────────────────────────────────────────┘
```

## What LySec Monitors

| Monitor | Coverage | Example alerts |
|---|---|---|
| USB | Device attach/detach via udev/sysfs | Unknown device, removable media |
| Login | auth.log/secure/wtmp/btmp | Root login, brute-force, sudo/su |
| Network | Listeners, interfaces, promisc mode | New listener, rogue NIC, sniffing |
| Process | Process table and UID changes | Suspicious binary, privilege escalation |
| Filesystem | Critical paths via inotify/watchdog | passwd/shadow/ssh/cron tampering |

## Why Detect-Only

1. Preserves evidence integrity.
2. Avoids interference with production systems.
3. Improves timeline reliability.
4. Complements prevention controls (iptables, SELinux, fail2ban).
5. Reduces outage risk from false positives.

## Installation

```bash
git clone <repo-url> && cd DF_Tool
sudo ./install.sh
```

Installer actions:
1. Creates isolated venv at `/opt/lysec/.venv`.
2. Installs package and dependencies.
3. Installs config at `/etc/lysec/lysec.yaml`.
4. Installs systemd unit `lysec.service`.
5. Creates command links in `/usr/local/bin`.

### PEP 668 note

On modern Debian/Ubuntu/Kali, system pip is externally managed. LySec avoids this by using
its own virtual environment.

If required:

```bash
sudo apt update
sudo apt install -y python3-venv
sudo ./install.sh
```

## Quick Start

```bash
sudo systemctl start lysec
sudo systemctl status lysec
sudo lysec status
sudo lysec alerts --last 1h
```

Run foreground debug mode:

```bash
sudo lysecd start --foreground
```

Launch GUI:

```bash
lysec-gui
```

## Operational Timeline Runbook

Use the following sequence in order during operations and investigations.

1. Load latest unit definitions.

```bash
sudo systemctl daemon-reload
```

Purpose: reloads systemd unit files after install/changes.
Analysis: continue only if no unit parse errors are shown.

2. Enable autostart.

```bash
sudo systemctl enable lysec
```

Purpose: starts LySec on every boot.
Analysis: confirm output contains created symlink and enabled state.

3. Start the daemon.

```bash
sudo systemctl start lysec
```

Purpose: launches LySec in background.
Analysis: if start fails, inspect service logs in step 5.

4. Verify service state.

```bash
sudo systemctl status lysec
```

Purpose: confirms active/running status and PID.
Analysis: good state is `active (running)`.

5. Live service event stream.

```bash
sudo journalctl -u lysec -f
```

Purpose: tails daemon/service logs in real time.
Analysis: look for monitor start lines and warnings/errors.

6. CLI health snapshot.

```bash
sudo lysec status
```

Purpose: LySec-level health and log directory visibility.
Analysis: confirms daemon detection and current log files.

7. Recent alerts (triage view).

```bash
sudo lysec alerts --last 30m
```

Purpose: fetches latest alert timeline.
Analysis: review by severity first: CRITICAL, HIGH, MEDIUM.

8. Full time-bounded timeline.

```bash
sudo lysec timeline --start 2026-03-22T00:00:00 --end 2026-03-22T23:59:59
```

Purpose: reconstructs host activity chronology for a fixed window.
Analysis: identify event chains across monitors.

9. Indicator pivots.

```bash
sudo lysec search --query "root"
sudo lysec search --query "192.168."
sudo lysec search --query "sudo"
```

Purpose: pivots investigation by user/IP/privilege indicators.
Analysis: repeated indicator across multiple event types increases confidence.

10. Export evidence artifacts.

```bash
sudo lysec export --format json --output /tmp/lysec_evidence.json --source all
sudo lysec export --format csv --output /tmp/lysec_timeline.csv --source all
```

Purpose: creates portable evidence for reporting and external analysis.
Analysis: prefer JSON for fidelity, CSV for quick spreadsheet review.

11. Validate evidence integrity.

```bash
sudo lysec verify
```

Purpose: checks log files against SHA-256 manifests.
Analysis: any tampered/missing result must be treated as an integrity incident.

12. Correlation analysis.

```bash
sudo lysec-eval --alerts-file /var/log/lysec/alerts.log --window-sec 300 --top 10 --output-json /tmp/lysec_eval.json --output-csv /tmp/lysec_eval_incidents.csv
sudo lysec-eval-plot --input-json /tmp/lysec_eval.json --output-dir /tmp/lysec_eval_plots
```

Purpose: groups related low-level alerts into higher-confidence incidents.
Analysis: prioritize highest scores and multi-monitor incidents.

13. End-of-session shutdown.

```bash
sudo systemctl stop lysec
sudo systemctl status lysec
```

Purpose: cleanly stops monitors and confirms state.
Analysis: expected final state is inactive/dead.

### Analysis Workflow

1. Define exact time window first.
2. Review alerts in that window.
3. Pivot by indicator (`ip`, `user`, `pid`, `path`, `serial`).
4. Confirm sequence in `timeline` output.
5. Export JSON/CSV evidence.
6. Run `lysec verify` before sharing evidence.
7. Run `lysec-eval` for campaign-level incident correlation.

## CLI Commands

```bash
sudo lysec status
sudo lysec alerts --severity HIGH --last 2h
sudo lysec timeline --start 2026-02-20T00:00:00 --end 2026-02-21T23:59:59
sudo lysec timeline --monitor usb
sudo lysec search --query "nmap"
sudo lysec export --format json --output /tmp/evidence.json
sudo lysec export --format csv --output /tmp/timeline.csv
sudo lysec verify
```

## Correlation Evaluation

Replay historical alerts and compare baseline vs FACES-v1 scoring:

```bash
sudo lysec-eval \
  --alerts-file /var/log/lysec/alerts.log \
  --window-sec 300 \
  --baseline-min-score 8 \
  --faces-min-score 45 \
  --output-json /tmp/lysec_eval.json \
  --output-csv /tmp/lysec_eval_incidents.csv \
  --top 10
```

Generate plots:

```bash
sudo lysec-eval-plot \
  --input-json /tmp/lysec_eval.json \
  --output-dir /tmp/lysec_eval_plots
```

## Configuration

Primary config file:

```bash
/etc/lysec/lysec.yaml
```

Reload config without full restart:

```bash
sudo systemctl reload lysec
```

## Log Format

Each line is JSON and SIEM-friendly:

```json
{
  "timestamp": "2026-02-21T14:30:00.123456+00:00",
  "epoch": 1771595400.123,
  "hostname": "forensic-ws",
  "level": "WARNING",
  "source": "lysec.monitor.usb",
  "message": "USB ATTACHED: SanDisk Ultra [0781:5583] serial=ABC123",
  "event_type": "USB_DEVICE_ATTACHED",
  "monitor": "usb",
  "severity": "HIGH"
}
```

## Integrity Verification

1. Rotated logs are hashed into `.sha256` manifests.
2. Run `lysec verify` to validate integrity.
3. Modified or missing files are flagged.

## Runtime Paths

| Path | Purpose |
|---|---|
| `/etc/lysec/lysec.yaml` | Main configuration |
| `/var/log/lysec/lysec.log` | Main event log |
| `/var/log/lysec/alerts.log` | Alert log |
| `/var/log/lysec/*.sha256` | Integrity manifests |
| `/var/lib/lysec/evidence/` | Evidence artifacts |
| `/var/run/lysec/lysecd.pid` | PID file |

## GUI Notes

The GUI (`lysec-gui`) provides:
1. Service controls (start, stop, restart).
2. Alerts table view.
3. Timeline viewer.

If GUI launch fails on minimal servers:

```bash
sudo apt install -y python3-tk
```

## Backward Compatibility

Legacy command aliases remain available:
1. `dftool`
2. `dftoold`
3. `dftool-eval`
4. `dftool-eval-plot`

## Uninstall

```bash
sudo ./uninstall.sh
```

Logs/evidence/config are intentionally preserved unless manually removed.

## License

MIT
