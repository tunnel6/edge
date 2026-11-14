#!/usr/bin/env bash
set -euo pipefail

# ============================================================
# Edge Install Script
# Download the Edge binary from GitHub Releases and configure the systemd service.
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/tunnel6/edge/main/scripts/install.sh | bash -s -- \
#     --startup-config "BASE64_CONFIG"
#
#   Or download it first and run:
#   bash install.sh --startup-config "BASE64_CONFIG" \
#     [--public-ip "1.2.3.4"] \
#     [--pair-token "TOKEN"] \
#     [--daemon] [--systemd=true] [--uninstall]
# ============================================================

GITHUB_REPO="tunnel6/edge"
INSTALL_DIR="/usr/local/bin"
BINARY_NAME="edge"
SERVICE_NAME="yat-edge"
DATA_DIR="/var/lib/edge"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ---- Argument parsing ----
STARTUP_CONFIG_B64=""
PUBLIC_IP=""
PAIR_TOKEN=""
DAEMON=false
SYSTEMD=true
UNINSTALL=false
VERSION="latest"
LOCAL_BINARY=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --startup-config)   STARTUP_CONFIG_B64="$2";  shift 2 ;;
    --public-ip)        PUBLIC_IP="$2";           shift 2 ;;
    --pair-token)       PAIR_TOKEN="$2";          shift 2 ;;
    --daemon)           DAEMON=true;              shift   ;;
    --systemd=true)     SYSTEMD=true;             shift   ;;
    --systemd=false)    SYSTEMD=false;            shift   ;;
    --systemd)          SYSTEMD="$2";             shift 2 ;;
    --version)          VERSION="$2";             shift 2 ;;
    --local-binary)     LOCAL_BINARY="$2";        shift 2 ;;
    --uninstall)        UNINSTALL=true;           shift   ;;
    -h|--help)
      echo "Usage: $0 [OPTIONS]"
      echo ""
      echo "Options:"
      echo "  --startup-config BASE64   Base64-encoded startup configuration (required)"
      echo "  --public-ip IP            Public IP address (optional; disables automatic detection)"
      echo "  --pair-token TOKEN        Preconfigured pairing token (optional)"
      echo "  --daemon                  Run as a background daemon"
      echo "  --systemd true|false      Whether to install the systemd service (default: true)"
      echo "  --version VERSION         Version to install (default: latest)"
      echo "  --local-binary PATH       Use a local binary (skips download)"
      echo "  --uninstall               Uninstall the Edge service"
      echo "  -h, --help                Show help"
      exit 0
      ;;
    *)
      log_error "Unknown argument: $1"
      exit 1
      ;;
  esac
done

# ---- Uninstall ----
if [ "$UNINSTALL" = true ]; then
  log_info "Uninstalling the Edge service..."
  if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"
    log_info "Stopped the $SERVICE_NAME service"
  fi
  if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME"
    log_info "Disabled the $SERVICE_NAME service"
  fi
  if [ -f "/etc/systemd/system/${SERVICE_NAME}.service" ]; then
    rm -f "/etc/systemd/system/${SERVICE_NAME}.service"
    systemctl daemon-reload
    log_info "Removed the service file"
  fi
  if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
    rm -f "${INSTALL_DIR}/${BINARY_NAME}"
    log_info "Removed the binary"
  fi
  log_info "Uninstall complete"
  exit 0
fi

# ---- Validate arguments ----
if [ -z "$STARTUP_CONFIG_B64" ]; then
  log_error "Missing required argument: --startup-config"
  exit 1
fi

# ---- Detect OS and architecture ----
detect_os() {
  local os
  os="$(uname -s | tr '[:upper:]' '[:lower:]')"
  case "$os" in
    linux)  echo "linux"  ;;
    darwin) echo "darwin" ;;
    *)      log_error "Unsupported operating system: $os"; exit 1 ;;
  esac
}

detect_arch() {
  local arch
  arch="$(uname -m)"
  case "$arch" in
    x86_64|amd64)   echo "amd64"  ;;
    aarch64|arm64)   echo "arm64"  ;;
    *)               log_error "Unsupported architecture: $arch"; exit 1 ;;
  esac
}

OS="$(detect_os)"
ARCH="$(detect_arch)"

# ---- Resolve version ----
resolve_version() {
  if [ "$VERSION" = "latest" ]; then
    local tag
    tag=$(curl -fsSL "https://api.github.com/repos/${GITHUB_REPO}/releases/latest" \
          | grep '"tag_name"' | head -1 | sed -E 's/.*"tag_name": *"([^"]+)".*/\1/')
    if [ -z "$tag" ]; then
      log_error "Unable to retrieve the latest version information"
      exit 1
    fi
    echo "$tag"
  else
    echo "$VERSION"
  fi
}

RESOLVED_VERSION="$(resolve_version)"
log_info "Target version: $RESOLVED_VERSION"

# ---- Download the binary ----
BINARY_URL="https://github.com/${GITHUB_REPO}/releases/download/${RESOLVED_VERSION}/edge-${OS}-${ARCH}"
CHECKSUM_URL="${BINARY_URL}.sha256"

download_binary() {
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  local tmp_binary="${tmp_dir}/${BINARY_NAME}"
  local tmp_checksum="${tmp_dir}/checksum"

  log_info "Downloading binary: $BINARY_URL"
  if ! curl -fsSL -o "$tmp_binary" "$BINARY_URL"; then
    log_error "Download failed: $BINARY_URL"
    rm -rf "$tmp_dir"
    exit 1
  fi

  # Verify the checksum when the checksum file is available.
  if curl -fsSL -o "$tmp_checksum" "$CHECKSUM_URL" 2>/dev/null; then
    log_info "Verifying file integrity..."
    local expected actual
    expected="$(awk '{print $1}' "$tmp_checksum")"
    actual="$(sha256sum "$tmp_binary" | awk '{print $1}')"
    if [ "$expected" != "$actual" ]; then
      log_error "Checksum mismatch!"
      rm -rf "$tmp_dir"
      exit 1
    fi
    log_info "Checksum verified"
  else
    log_warn "Checksum file unavailable; skipping integrity verification"
  fi

  # Install the binary.
  chmod +x "$tmp_binary"
  mv "$tmp_binary" "${INSTALL_DIR}/${BINARY_NAME}"
  rm -rf "$tmp_dir"
  log_info "Installed to ${INSTALL_DIR}/${BINARY_NAME}"
}

# Install from a local binary when provided.
if [ -n "$LOCAL_BINARY" ]; then
  if [ ! -f "$LOCAL_BINARY" ]; then
    log_error "Local binary not found: $LOCAL_BINARY"
    exit 1
  fi
  chmod +x "$LOCAL_BINARY"
  cp "$LOCAL_BINARY" "${INSTALL_DIR}/${BINARY_NAME}"
  log_info "Installed local binary: $LOCAL_BINARY -> ${INSTALL_DIR}/${BINARY_NAME}"
else
  # Skip downloading when the requested version is already installed.
  if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ] && [ "$VERSION" != "latest" ]; then
    CURRENT_VERSION="$("${INSTALL_DIR}/${BINARY_NAME}" version 2>/dev/null || echo "unknown")"
    if [ "$CURRENT_VERSION" = "$RESOLVED_VERSION" ]; then
      log_info "Same version already installed; skipping download"
    else
      download_binary
    fi
  else
    download_binary
  fi
fi

# ---- Create the data directory ----
if [ ! -d "$DATA_DIR" ]; then
  mkdir -p "$DATA_DIR"
  log_info "Created data directory: $DATA_DIR"
fi

# ---- Install the systemd service ----
if [ "$SYSTEMD" = "true" ]; then
  if ! command -v systemctl &>/dev/null; then
    log_warn "systemctl is unavailable; skipping systemd service installation"
    SYSTEMD="false"
  fi
fi

if [ "$SYSTEMD" = "true" ]; then
  log_info "Installing systemd service: $SERVICE_NAME"

  cat > "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
[Unit]
Description=Edge Tunnel Server
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=root
Group=root
EOF

  # Add the optional public IP environment variable.
  if [ -n "$PUBLIC_IP" ]; then
    echo "Environment=PUBLIC_IP=${PUBLIC_IP}" >> "/etc/systemd/system/${SERVICE_NAME}.service"
    log_info "Set public IP: $PUBLIC_IP"
  fi

  # Add the pairing token environment variable.
  if [ -n "$PAIR_TOKEN" ]; then
    echo "Environment=PAIR_TOKEN=${PAIR_TOKEN}" >> "/etc/systemd/system/${SERVICE_NAME}.service"
    log_info "Set pairing token"
  fi

  # Append ExecStart and the remaining service configuration.
  cat >> "/etc/systemd/system/${SERVICE_NAME}.service" <<EOF
ExecStart=${INSTALL_DIR}/${BINARY_NAME} server start --startup.config_b64=${STARTUP_CONFIG_B64}
Restart=always
RestartSec=5
WorkingDirectory=${DATA_DIR}
StandardOutput=journal
StandardError=journal
SyslogIdentifier=edge

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${DATA_DIR} /var/log /tmp
RestrictNamespaces=true
LockPersonality=true
MemoryDenyWriteExecute=true
RestrictRealtime=true
RestrictSUIDSGID=true

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable "$SERVICE_NAME"
  systemctl start "$SERVICE_NAME"
  log_info "Service started"

  sleep 2
  if systemctl is-active --quiet "$SERVICE_NAME"; then
    log_info "The Edge service is running"
  else
    log_warn "The Edge service may not have started. Check: journalctl -u $SERVICE_NAME -n 50"
  fi
fi

# ---- Run directly without systemd ----
if [ "$SYSTEMD" != "true" ]; then
  # Export the shared environment variables.
  if [ -n "$PUBLIC_IP" ]; then
    export PUBLIC_IP="$PUBLIC_IP"
  fi
  if [ -n "$PAIR_TOKEN" ]; then
    export PAIR_TOKEN="$PAIR_TOKEN"
  fi

  if [ "$DAEMON" = true ]; then
    log_info "Starting Edge in background mode..."
    nohup "${INSTALL_DIR}/${BINARY_NAME}" server start \
      --startup.config_b64="${STARTUP_CONFIG_B64}" \
      > /var/log/edge.log 2>&1 &
    log_info "Edge started in the background. Logs: /var/log/edge.log"
  else
    log_info "Starting Edge (foreground mode)..."
    exec "${INSTALL_DIR}/${BINARY_NAME}" server start \
      --startup.config_b64="${STARTUP_CONFIG_B64}"
  fi
fi

log_info "Installation complete!"
echo ""
echo "  Status:      systemctl status $SERVICE_NAME"
echo "  Logs:        journalctl -u $SERVICE_NAME -f"
echo "  Uninstall:   $0 --uninstall"
echo ""
