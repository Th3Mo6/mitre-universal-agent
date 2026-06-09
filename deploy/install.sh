#!/usr/bin/env bash
#
# Universal MITRE AI Agent — Ubuntu installer
# -------------------------------------------------------------------------
# Installs the agent and ALL prerequisites, registers a systemd service,
# starts it, and prints the web control-panel URL (with access token).
#
# Usage:
#   sudo ./deploy/install.sh                 # install + start
#   sudo AGENT_PORT=9000 ./deploy/install.sh # custom port
#
# Tested on Ubuntu 22.04 / 24.04. Requires root (sudo).
# The agent itself has NO third-party runtime deps (Python stdlib only).
# -------------------------------------------------------------------------
set -euo pipefail

# ---- settings (override via env) ----------------------------------------
INSTALL_DIR="${INSTALL_DIR:-/opt/mitre-agent}"
DATA_DIR="${DATA_DIR:-/var/lib/mitre-agent}"
ENV_DIR="${ENV_DIR:-/etc/mitre-agent}"
SERVICE_USER="${SERVICE_USER:-mitre}"
AGENT_HOST="${AGENT_HOST:-0.0.0.0}"
AGENT_PORT="${AGENT_PORT:-8080}"
AGENT_AUTOSTART="${AGENT_AUTOSTART:-1}"
PY="python3.12"

log()  { printf '\033[1;34m[*]\033[0m %s\n' "$*"; }
ok()   { printf '\033[1;32m[+]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[!]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[x]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Please run as root:  sudo $0"

# Project root = parent of this script's directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
[ -f "$SRC_DIR/app.py" ] || die "app.py not found in $SRC_DIR — run from the project tree."

# ---- 1. base packages ---------------------------------------------------
log "Updating apt and installing base packages..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -y
apt-get install -y software-properties-common ca-certificates rsync curl

# ---- 2. Python 3.12 -----------------------------------------------------
if ! command -v "$PY" >/dev/null 2>&1; then
  log "Python 3.12 not found; installing..."
  if ! apt-get install -y python3.12 python3.12-venv 2>/dev/null; then
    warn "python3.12 not in default repos; adding deadsnakes PPA."
    add-apt-repository -y ppa:deadsnakes/ppa
    apt-get update -y
    apt-get install -y python3.12 python3.12-venv
  fi
else
  # Ensure the venv module is present for the detected interpreter.
  apt-get install -y python3.12-venv || true
fi
command -v "$PY" >/dev/null 2>&1 || die "Python 3.12 installation failed."
"$PY" -c 'import sys; assert sys.version_info >= (3,12)' \
  || die "Interpreter $PY is older than 3.12."
ok "Using $($PY --version)"

# ---- 3. service user & directories --------------------------------------
if ! id "$SERVICE_USER" >/dev/null 2>&1; then
  log "Creating system user '$SERVICE_USER'..."
  useradd --system --home "$INSTALL_DIR" --shell /usr/sbin/nologin "$SERVICE_USER"
fi
mkdir -p "$INSTALL_DIR" "$DATA_DIR" "$ENV_DIR"

# ---- 4. copy application ------------------------------------------------
log "Copying application to $INSTALL_DIR ..."
rsync -a --delete \
  --exclude '.git' --exclude '.venv' --exclude 'venv' \
  --exclude '__pycache__' --exclude '.pytest_cache' --exclude '.mypy_cache' \
  --exclude 'dist' --exclude 'results.jsonl' \
  "$SRC_DIR"/ "$INSTALL_DIR"/

# ---- 5. virtual environment --------------------------------------------
log "Creating virtual environment..."
"$PY" -m venv "$INSTALL_DIR/venv"
"$INSTALL_DIR/venv/bin/python" -m pip install --upgrade pip >/dev/null
# The agent has no third-party runtime deps; install the package if a wheel
# build is desired (optional, ignored on failure since stdlib-only works).
if [ -f "$INSTALL_DIR/pyproject.toml" ]; then
  "$INSTALL_DIR/venv/bin/pip" install "$INSTALL_DIR" >/dev/null 2>&1 \
    || warn "Editable/package install skipped — running directly from app.py (OK)."
fi
ok "Environment ready."

# ---- 6. environment file (token + settings) -----------------------------
TOKEN="$(head -c 32 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | head -c 32)"
log "Writing $ENV_DIR/agent.env ..."
cat > "$ENV_DIR/agent.env" <<EOF
AGENT_CONFIG=$INSTALL_DIR/config/default.json
AGENT_RESULTS=$DATA_DIR/results.jsonl
AGENT_HOST=$AGENT_HOST
AGENT_PORT=$AGENT_PORT
AGENT_TOKEN=$TOKEN
AGENT_AUTOSTART=$AGENT_AUTOSTART
EOF
chmod 640 "$ENV_DIR/agent.env"

# ---- 7. permissions -----------------------------------------------------
chown -R "$SERVICE_USER":"$SERVICE_USER" "$INSTALL_DIR" "$DATA_DIR"
chown -R root:"$SERVICE_USER" "$ENV_DIR"

# ---- 8. systemd service -------------------------------------------------
log "Installing systemd service..."
install -m 644 "$INSTALL_DIR/deploy/mitre-agent.service" \
  /etc/systemd/system/mitre-agent.service
systemctl daemon-reload
systemctl enable --now mitre-agent.service

# ---- 9. firewall (best-effort) ------------------------------------------
if command -v ufw >/dev/null 2>&1 && ufw status | grep -q "Status: active"; then
  log "Opening port $AGENT_PORT in ufw..."
  ufw allow "${AGENT_PORT}/tcp" >/dev/null || warn "ufw rule add failed (continuing)."
fi

# ---- 10. summary --------------------------------------------------------
sleep 2
LAN_IP="$(hostname -I 2>/dev/null | awk '{print $1}')"; LAN_IP="${LAN_IP:-localhost}"
echo
echo "================================================================"
if systemctl is-active --quiet mitre-agent.service; then
  ok "mitre-agent service is RUNNING."
else
  warn "Service not active yet — check: journalctl -u mitre-agent -e"
fi
echo "  Control panel (local):   http://localhost:$AGENT_PORT/?token=$TOKEN"
echo "  Control panel (network): http://$LAN_IP:$AGENT_PORT/?token=$TOKEN"
echo "  Access token:            $TOKEN"
echo "  Config file:             $INSTALL_DIR/config/default.json"
echo "  Results:                 $DATA_DIR/results.jsonl"
echo "----------------------------------------------------------------"
echo "  Status:   systemctl status mitre-agent"
echo "  Logs:     journalctl -u mitre-agent -f"
echo "  Restart:  systemctl restart mitre-agent"
echo "  Remove:   sudo $INSTALL_DIR/deploy/uninstall.sh"
echo "================================================================"
