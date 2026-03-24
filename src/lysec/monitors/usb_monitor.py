"""
LySec - USB Monitor
Detects USB device attach / detach events using pyudev (Linux udev).
Logs full device metadata and raises alerts for unknown devices.

Forensic value:
    * Tracks every USB mass-storage, HID, network adapter plug event.
    * Evidence of data exfiltration via removable media.
    * Evidence of BadUSB / Rubber-Ducky style attacks.

NOTE: Detection & Logging ONLY — no device blocking.
"""

import json
import logging
import os
import time
from datetime import datetime, timezone

from lysec.monitors.base import BaseMonitor
from lysec.alert_engine import SEVERITY_HIGH, SEVERITY_INFO, SEVERITY_MEDIUM

logger = logging.getLogger("lysec.monitor.usb")


class USBMonitor(BaseMonitor):
    name = "usb"

    def __init__(self, config: dict, alert_engine):
        super().__init__(config, alert_engine)
        self._mon_cfg = config.get("monitors", {}).get("usb", {})
        self._whitelist: set[str] = set(self._mon_cfg.get("whitelist", []))
        self._known_devices: dict[str, dict] = {}  # sys_path -> info
        self._udev_monitor = None
        self._context = None
        # Track previously seen device paths for reliable change detection
        self._prev_device_paths: set[str] = set()
        # Track device file permissions for change detection
        self._device_perms: dict[str, str] = {}  # dev_path -> octal_perms

    # ── Setup ──
    def setup(self):
        try:
            import pyudev

            self._context = pyudev.Context()
            # Take initial inventory
            self._snapshot_devices()
            # Take baseline of device file permissions
            self._device_perms = self._get_all_device_perms()
            logger.info(
                "USB monitor initialised — %d device(s) present, %d device file(s) tracked",
                len(self._known_devices),
                len(self._device_perms),
            )
        except ImportError:
            logger.warning(
                "pyudev not installed — falling back to /sys/bus/usb polling"
            )
            # Still track device file permissions even without pyudev
            self._device_perms = self._get_all_device_perms()
        except Exception as exc:
            logger.error("USB monitor setup error: %s", exc)

    # ── Poll ──
    def poll(self):
        if self._context is not None:
            self._poll_udev()
            self._check_device_perms()  # Check for permission changes
        else:
            self._poll_sysfs()
            self._check_device_perms()  # Check for permission changes

    # ──────────────────────── udev-based polling ────────────────────────
    def _poll_udev(self):
        import pyudev

        current: dict[str, dict] = {}
        for device in self._context.list_devices(subsystem="usb", DEVTYPE="usb_device"):
            info = self._extract_udev_info(device)
            current[device.sys_path] = info

        current_paths = set(current.keys())

        # New devices
        for path in current_paths - self._prev_device_paths:
            info = current[path]
            self._on_device_added(info)

        # Removed devices
        for path in self._prev_device_paths - current_paths:
            info = self._known_devices.get(path, {"sys_path": path})
            self._on_device_removed(info)

        self._known_devices = current
        self._prev_device_paths = current_paths

    def _extract_udev_info(self, device) -> dict:
        return {
            "sys_path": device.sys_path,
            "vendor_id": device.get("ID_VENDOR_ID", ""),
            "product_id": device.get("ID_MODEL_ID", ""),
            "vendor": device.get(
                "ID_VENDOR_FROM_DATABASE", device.get("ID_VENDOR", "")
            ),
            "model": device.get("ID_MODEL_FROM_DATABASE", device.get("ID_MODEL", "")),
            "serial": device.get("ID_SERIAL_SHORT", ""),
            "bus_num": device.get("BUSNUM", ""),
            "dev_num": device.get("DEVNUM", ""),
            "driver": device.get("DRIVER", ""),
            "device_class": device.get("bDeviceClass", ""),
        }

    # ──────────────────────── sysfs fallback polling ────────────────────
    def _poll_sysfs(self):
        current: dict[str, dict] = {}
        usb_base = "/sys/bus/usb/devices"
        if not os.path.isdir(usb_base):
            return

        for entry in os.listdir(usb_base):
            dev_path = os.path.join(usb_base, entry)
            vendor_file = os.path.join(dev_path, "idVendor")
            if not os.path.isfile(vendor_file):
                continue
            info = self._read_sysfs_device(dev_path, entry)
            current[dev_path] = info

        current_paths = set(current.keys())

        for path in current_paths - self._prev_device_paths:
            info = current[path]
            self._on_device_added(info)

        for path in self._prev_device_paths - current_paths:
            info = self._known_devices.get(path, {"sys_path": path})
            self._on_device_removed(info)

        self._known_devices = current
        self._prev_device_paths = current_paths

    def _read_sysfs_device(self, path: str, name: str) -> dict:
        def _read(filename):
            fp = os.path.join(path, filename)
            try:
                return open(fp).read().strip()
            except Exception:
                return ""

        return {
            "sys_path": path,
            "name": name,
            "vendor_id": _read("idVendor"),
            "product_id": _read("idProduct"),
            "manufacturer": _read("manufacturer"),
            "product": _read("product"),
            "serial": _read("serial"),
            "bus_num": _read("busnum"),
            "dev_num": _read("devnum"),
        }

    # ──────────────────────── Event handlers ────────────────────────────
    def _on_device_added(self, info: dict):
        vid_pid = f"{info.get('vendor_id', '')}:{info.get('product_id', '')}"
        is_whitelisted = vid_pid in self._whitelist

        logger.info(
            "USB ATTACHED: %s [%s] serial=%s whitelisted=%s",
            info.get("model") or info.get("product", "unknown"),
            vid_pid,
            info.get("serial", "N/A"),
            is_whitelisted,
        )

        if self._mon_cfg.get("alert_on_new_device") and not is_whitelisted:
            self._alert.fire(
                monitor="usb",
                event_type="USB_DEVICE_ATTACHED",
                message=f"Unknown USB device attached: {vid_pid} "
                f"({info.get('model') or info.get('product', 'unknown')})",
                severity=SEVERITY_HIGH,
                details=info,
            )
        else:
            self._alert.fire(
                monitor="usb",
                event_type="USB_DEVICE_ATTACHED",
                message=f"Known USB device attached: {vid_pid}",
                severity=SEVERITY_INFO,
                details=info,
            )

    def _on_device_removed(self, info: dict):
        vid_pid = f"{info.get('vendor_id', '')}:{info.get('product_id', '')}"
        logger.info("USB REMOVED: %s [%s]", info.get("model", "unknown"), vid_pid)

        self._alert.fire(
            monitor="usb",
            event_type="USB_DEVICE_REMOVED",
            message=f"USB device removed: {vid_pid}",
            severity=SEVERITY_INFO,
            details=info,
        )

    # ──────────────────────── Permission Change Monitoring ──────────────
    def _check_device_perms(self):
        """Check for permission changes on USB device files."""
        current_perms = self._get_all_device_perms()

        for dev_path, perms in current_perms.items():
            if dev_path not in self._device_perms:
                # New device file tracked
                self._device_perms[dev_path] = perms
            elif self._device_perms[dev_path] != perms:
                # Permission changed
                old_perms = self._device_perms[dev_path]
                self._on_device_perm_changed(dev_path, old_perms, perms)
                self._device_perms[dev_path] = perms

        # Clean up removed device files
        for dev_path in list(self._device_perms.keys()):
            if dev_path not in current_perms:
                del self._device_perms[dev_path]

    def _get_all_device_perms(self) -> dict[str, str]:
        """Get current permissions for all USB device files."""
        perms = {}

        # Scan /dev for USB device files (sdX, sdX1-9, etc.)
        try:
            for entry in os.listdir("/dev"):
                # Look for SD/USB block devices
                if entry.startswith("sd"):
                    dev_path = f"/dev/{entry}"
                    if os.path.exists(dev_path):
                        try:
                            stat_info = os.stat(dev_path)
                            mode_octal = oct(stat_info.st_mode)[
                                -3:
                            ]  # Last 3 octal digits
                            perms[dev_path] = mode_octal
                        except (OSError, PermissionError):
                            pass

                # Look for other USB block devices (tty, etc.)
                elif entry.startswith("ttyUSB"):
                    dev_path = f"/dev/{entry}"
                    if os.path.exists(dev_path):
                        try:
                            stat_info = os.stat(dev_path)
                            mode_octal = oct(stat_info.st_mode)[-3:]
                            perms[dev_path] = mode_octal
                        except (OSError, PermissionError):
                            pass
        except OSError:
            pass

        return perms

    def _on_device_perm_changed(self, dev_path: str, old_perms: str, new_perms: str):
        """Alert when USB device file permissions change."""
        logger.warning(
            "USB device permissions changed: %s [%s -> %s]",
            dev_path,
            old_perms,
            new_perms,
        )

        self._alert.fire(
            monitor="usb",
            event_type="USB_DEVICE_PERM_CHANGED",
            message=f"USB device permissions changed: {dev_path} ({old_perms} -> {new_perms})",
            severity=SEVERITY_HIGH,
            details={
                "device_path": dev_path,
                "old_permissions": old_perms,
                "new_permissions": new_perms,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
        )

    # ──────────────────────── Helpers ───────────────────────────────────
    def _snapshot_devices(self):
        """Take initial snapshot so we don't alert on boot-time devices."""
        if self._context:
            import pyudev

            for device in self._context.list_devices(
                subsystem="usb", DEVTYPE="usb_device"
            ):
                info = self._extract_udev_info(device)
                self._known_devices[device.sys_path] = info
                self._prev_device_paths.add(device.sys_path)
        logger.info("Initial USB snapshot: %d devices", len(self._known_devices))
