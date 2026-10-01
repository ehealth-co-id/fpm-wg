#!/usr/bin/env bash
set -euo pipefail

# Configuration
REPO="ehealth-co-id/fpm-wg"
SERVICE_NAME="fpm-wg"
BINARY="fpm-wg"
INSTALL_DIR="/usr/local/bin"
CONFIG_DIR="/etc/fpm-wg"
CONFIG_FILE="${CONFIG_DIR}/config.json"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"

# Optional: a token is only needed for private forks.
TOKEN="${GITHUB_TOKEN:-${GH_TOKEN:-}}"

echo "[*] Installing ${SERVICE_NAME} from latest release..."

# 1. Pre-flight checks
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: This script must be run as root"
  exit 1
fi

case "$(uname -m)" in
  x86_64) GOARCH="amd64" ;;
  aarch64|arm64) GOARCH="arm64" ;;
  *)
    echo "ERROR: Unsupported architecture: $(uname -m)"
    exit 1
    ;;
esac

ASSET_NAME="${BINARY}-linux-${GOARCH}"

# 2. Fetch latest release information
echo "[*] Fetching latest release information..."
AUTH=()
if [[ -n "$TOKEN" ]]; then
  AUTH=(-H "Authorization: Bearer ${TOKEN}")
fi

RELEASE_JSON=$(curl -fsSL "${AUTH[@]}" \
  -H "Accept: application/vnd.github+json" \
  -H "User-Agent: fpm-wg-install" \
  "https://api.github.com/repos/${REPO}/releases/latest")

if [[ -n "$TOKEN" ]]; then
  # Private repo: the browser_download_url is not reachable; use the asset API.
  ASSET_URL=$(printf '%s' "$RELEASE_JSON" \
    | grep -oE "\"url\":\"https://api\.github\.com/repos/[^\"]*/releases/assets/[0-9]+\"[^{]*\"name\":\"${ASSET_NAME}\"" \
    | head -1 \
    | grep -oE 'https://[^"]+/releases/assets/[0-9]+')
  DL=(-H "Authorization: Bearer ${TOKEN}" -H "Accept: application/octet-stream")
else
  ASSET_URL=$(printf '%s' "$RELEASE_JSON" \
    | grep -oE "https://[^\"]+/${ASSET_NAME}\"" | head -1 | tr -d '"')
  DL=()
fi

if [[ -z "${ASSET_URL:-}" ]]; then
  echo "ERROR: Could not find release asset ${ASSET_NAME}"
  exit 1
fi

echo "[*] Downloading release from: $ASSET_URL"

# Stop service if it exists to allow file overwrite
systemctl stop "${SERVICE_NAME}" 2>/dev/null || true

# 3. Install binary
echo "[*] Installing to ${INSTALL_DIR}/${BINARY}..."
install -d "${INSTALL_DIR}"
curl -fsSL "${DL[@]}" -o "${INSTALL_DIR}/${BINARY}" "$ASSET_URL"
chmod 755 "${INSTALL_DIR}/${BINARY}"

# 4. Config (write a default if absent; never overwrite an existing one)
install -d -m 0755 "${CONFIG_DIR}"
if [[ ! -f "${CONFIG_FILE}" ]]; then
  echo "[*] Writing default config to ${CONFIG_FILE}"
  cat > "${CONFIG_FILE}" <<'JSON'
{
  "listen": "127.0.0.1:2620",
  "interface": "wg0",
  "tunnel_net": "",
  "applier": "ctrl",
  "flush_interval": "100ms",
  "log_level": "info"
}
JSON
  chmod 0644 "${CONFIG_FILE}"
  echo "WARNING: set \"tunnel_net\" to the CIDR holding your peer tunnel /32s"
  echo "         and confirm \"interface\" before relying on the service."
fi

# 5. Systemd setup
echo "[*] Configuring systemd service..."

cat > "$SERVICE_FILE" <<EOF
[Unit]
Description=fpm-wg - sync WireGuard allowed-ips from FRR dplane_fpm_nl
Documentation=https://github.com/${REPO}
After=network-online.target wg-quick@wg0.service frr.service
Wants=network-online.target wg-quick@wg0.service

[Service]
Type=simple
ExecStart=${INSTALL_DIR}/${BINARY} -config ${CONFIG_FILE}
Restart=on-failure
RestartSec=2
TimeoutStartSec=10

# Programming WireGuard requires root (netlink).
User=root

# Hardening (compatible with netlink + wg socket access)
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadOnlyPaths=${CONFIG_DIR}
RestrictAddressFamilies=AF_INET AF_UNIX AF_NETLINK

# Logging
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[*] Reloading systemd"
systemctl daemon-reload

echo "[*] Enabling service"
systemctl enable "${SERVICE_NAME}"

if [[ -f "${CONFIG_FILE}" ]]; then
  echo "[*] Starting service"
  systemctl restart "${SERVICE_NAME}"
else
  echo "[*] Skipping start — create ${CONFIG_FILE} first, then run:"
  echo "    systemctl start ${SERVICE_NAME}"
fi

echo "[✓] Done"
echo "    status:  systemctl status ${SERVICE_NAME}"
echo "    logs:    journalctl -u ${SERVICE_NAME} -f"
echo ""
echo "Reminder: FRR must have '-M dplane_fpm_nl' in zebra_options and"
echo "'fpm address 127.0.0.1 port 2620' in frr.conf (see the repo README)."
