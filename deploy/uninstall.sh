#!/usr/bin/env bash
#
# Universal MITRE AI Agent — uninstaller
#   sudo ./deploy/uninstall.sh            # stop + remove service, keep data
#   sudo PURGE=1 ./deploy/uninstall.sh    # also remove install/data/user
#
set -euo pipefail

INSTALL_DIR="${INSTALL_DIR:-/opt/mitre-agent}"
DATA_DIR="${DATA_DIR:-/var/lib/mitre-agent}"
ENV_DIR="${ENV_DIR:-/etc/mitre-agent}"
SERVICE_USER="${SERVICE_USER:-mitre}"
PURGE="${PURGE:-0}"

[ "$(id -u)" -eq 0 ] || { echo "Run as root: sudo $0" >&2; exit 1; }

echo "[*] Stopping service..."
systemctl disable --now mitre-agent.service 2>/dev/null || true
rm -f /etc/systemd/system/mitre-agent.service
systemctl daemon-reload

if [ "$PURGE" = "1" ]; then
  echo "[*] Purging install, data, env, and user..."
  rm -rf "$INSTALL_DIR" "$DATA_DIR" "$ENV_DIR"
  if id "$SERVICE_USER" >/dev/null 2>&1; then userdel "$SERVICE_USER" 2>/dev/null || true; fi
  echo "[+] Fully removed."
else
  echo "[+] Service removed. Kept $INSTALL_DIR and $DATA_DIR (use PURGE=1 to delete)."
fi
