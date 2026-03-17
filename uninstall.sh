#!/usr/bin/env bash
# DFTool Uninstaller
set -euo pipefail

echo "Stopping DFTool daemon …"
systemctl stop dftool.service 2>/dev/null || true
systemctl disable dftool.service 2>/dev/null || true

echo "Removing systemd service …"
rm -f /etc/systemd/system/dftool.service
systemctl daemon-reload

echo "Removing Python package …"
pip3 uninstall -y dftool 2>/dev/null || true

echo "Removing installation files …"
rm -rf /opt/dftool

echo ""
echo "DFTool uninstalled."
echo ""
echo "The following directories were NOT removed (contain forensic data):"
echo "  /var/log/dftool/         — log files"
echo "  /var/lib/dftool/         — evidence"
echo "  /etc/dftool/             — configuration"
echo ""
echo "Remove them manually if no longer needed:"
echo "  sudo rm -rf /var/log/dftool /var/lib/dftool /etc/dftool"
