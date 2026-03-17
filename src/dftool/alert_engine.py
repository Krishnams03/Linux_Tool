"""
DFTool - Alert Engine
Centralized alert dispatcher.  Monitors push events here; the engine
formats, deduplicates, and fans out to configured channels (log, syslog,
email, webhook).

Design: DETECT & LOG only — alerts are informational, never preventive.
"""

import json
import logging
import os
import smtplib
import time
import uuid
from datetime import datetime, timezone
from email.mime.text import MIMEText
from pathlib import Path
from typing import Any

try:
    import urllib.request
    HAS_URLLIB = True
except ImportError:
    HAS_URLLIB = False

logger = logging.getLogger("dftool.alerts")

# ──────────────────────────────────────────────
# Severity levels (VERIS-inspired)
# ──────────────────────────────────────────────
SEVERITY_INFO = "INFO"
SEVERITY_LOW = "LOW"
SEVERITY_MEDIUM = "MEDIUM"
SEVERITY_HIGH = "HIGH"
SEVERITY_CRITICAL = "CRITICAL"


class AlertEngine:
    """
    Singleton-style alert dispatcher.
    """

    def __init__(self, config: dict):
        self._config = config.get("alerts", {})
        self._alert_log_path = self._config.get(
            "alert_log", "/var/log/dftool/alerts.log"
        )
        Path(os.path.dirname(self._alert_log_path)).mkdir(
            parents=True, exist_ok=True
        )
        # Simple dedup: hash(monitor+event_type+key_detail) -> last_ts
        self._seen: dict[str, float] = {}
        self._dedup_window = 60  # seconds

    # ──────────────────────────────────────────
    # Public API
    # ──────────────────────────────────────────
    def fire(
        self,
        monitor: str,
        event_type: str,
        message: str,
        severity: str = SEVERITY_MEDIUM,
        details: dict[str, Any] | None = None,
    ):
        """
        Create and dispatch an alert.
        """
        alert_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)

        alert = {
            "alert_id": alert_id,
            "timestamp": now_utc.isoformat(),
            "epoch": time.time(),
            "monitor": monitor,
            "event_type": event_type,
            "severity": severity,
            "message": message,
            "details": details or {},
        }

        # Deduplication
        dedup_key = f"{monitor}:{event_type}:{json.dumps(details, sort_keys=True, default=str)}"
        last = self._seen.get(dedup_key, 0)
        if time.time() - last < self._dedup_window:
            return  # suppress duplicate
        self._seen[dedup_key] = time.time()

        # ── Dispatch ──
        self._write_alert_log(alert)
        self._log_alert(alert)

        if self._config.get("syslog", False):
            self._send_syslog(alert)

        email_cfg = self._config.get("email", {})
        if email_cfg.get("enabled", False):
            self._send_email(alert, email_cfg)

        webhook_cfg = self._config.get("webhook", {})
        if webhook_cfg.get("enabled", False):
            self._send_webhook(alert, webhook_cfg)

    # ──────────────────────────────────────────
    # Dispatch backends
    # ──────────────────────────────────────────
    def _write_alert_log(self, alert: dict):
        """Append JSON alert to dedicated alert log file."""
        try:
            with open(self._alert_log_path, "a") as f:
                f.write(json.dumps(alert, default=str) + "\n")
        except Exception as exc:
            logger.error("Failed to write alert log: %s", exc)

    def _log_alert(self, alert: dict):
        """Forward alert to the main forensic logger."""
        level = {
            SEVERITY_INFO: logging.INFO,
            SEVERITY_LOW: logging.INFO,
            SEVERITY_MEDIUM: logging.WARNING,
            SEVERITY_HIGH: logging.ERROR,
            SEVERITY_CRITICAL: logging.CRITICAL,
        }.get(alert["severity"], logging.WARNING)

        logger.log(
            level,
            "[ALERT %s] [%s] %s",
            alert["severity"],
            alert["monitor"],
            alert["message"],
            extra={
                "event_type": alert["event_type"],
                "monitor": alert["monitor"],
                "details": alert["details"],
                "severity": alert["severity"],
                "alert_id": alert["alert_id"],
            },
        )

    def _send_syslog(self, alert: dict):
        """Already handled by forensic_logger syslog handler."""
        pass

    def _send_email(self, alert: dict, cfg: dict):
        """Send alert via SMTP."""
        try:
            subject = f"[DFTool {alert['severity']}] {alert['event_type']} on {alert['monitor']}"
            body = json.dumps(alert, indent=2, default=str)
            msg = MIMEText(body)
            msg["Subject"] = subject
            msg["From"] = cfg["from_addr"]
            msg["To"] = cfg["to_addr"]

            with smtplib.SMTP(cfg["smtp_server"], cfg["smtp_port"]) as server:
                server.starttls()
                server.login(cfg["username"], cfg["password"])
                server.sendmail(cfg["from_addr"], [cfg["to_addr"]], msg.as_string())
        except Exception as exc:
            logger.error("Email alert failed: %s", exc)

    def _send_webhook(self, alert: dict, cfg: dict):
        """POST JSON alert to a webhook URL."""
        if not HAS_URLLIB:
            return
        try:
            data = json.dumps(alert, default=str).encode("utf-8")
            req = urllib.request.Request(
                cfg["url"],
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            urllib.request.urlopen(req, timeout=10)
        except Exception as exc:
            logger.error("Webhook alert failed: %s", exc)
