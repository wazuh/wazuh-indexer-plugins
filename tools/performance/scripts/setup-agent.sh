#!/bin/bash
#
# setup-agent.sh — install + enroll a Wazuh agent, and configure it to watch the
# FIM + Logcollector load paths used by the performance scenario.
#
# A single --version flag selects the source; the flow is identical for both:
#   - 5.x  → latest staging nightly agent package (resolved from the artifacts YAML)
#   - 4.x  → official packages.wazuh.com 4.x repository
#
#   sudo ./setup-agent.sh --version 5.0.0 --manager <aio-ip>
#   sudo ./setup-agent.sh --version 4.14  --manager <aio-ip>
#
# Run as root on each agent host, pointing at the AIO manager IP.
#
set -e

VERSION="5.0.0"
MANAGER=""
FIM_DIR="/var/perf-fim"
LOG_FILE="/var/perf-logs/load.log"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)  VERSION="$2"; shift 2 ;;
        --manager)  MANAGER="$2"; shift 2 ;;
        --fim-dir)  FIM_DIR="$2"; shift 2 ;;
        --log-file) LOG_FILE="$2"; shift 2 ;;
        *) echo "Usage: $0 --manager IP [--version X.Y.Z] [--fim-dir D] [--log-file F]"; exit 1 ;;
    esac
done

if [[ -z "$MANAGER" ]]; then
    echo "[ERROR] --manager <AIO manager IP> is required." >&2
    exit 1
fi

# --- Detect architecture & package type --------------------------------------
ARCH=$(uname -m)
if command -v rpm >/dev/null 2>&1; then
    PKG_TYPE="rpm"
    case "$ARCH" in amd64) ARCH="x86_64" ;; arm64) ARCH="aarch64" ;; esac
elif command -v dpkg >/dev/null 2>&1; then
    PKG_TYPE="deb"
    case "$ARCH" in x86_64) ARCH="amd64" ;; aarch64) ARCH="arm64" ;; armv7l) ARCH="armhf" ;; esac
else
    echo "[ERROR] Neither rpm nor dpkg found — cannot install." >&2
    exit 1
fi
echo "[INFO] Version: $VERSION | Architecture: $ARCH | Package type: $PKG_TYPE | Manager: $MANAGER"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

# --- Install + enroll the agent for the requested version --------------------
case "$VERSION" in
    5.*)
        # Staging nightly: resolve the agent package URL from the artifacts YAML.
        ARTIFACTS_URL="https://packages-staging.xdrsiem.wazuh.info/nightly/${VERSION}/artifact-urls/artifact_urls_${VERSION}-latest.yaml"
        ARTIFACTS_FILE="$WORKDIR/artifact_urls.yaml"
        echo "[INFO] Downloading artifacts YAML: $ARTIFACTS_URL"
        curl -sS --fail -L "$ARTIFACTS_URL" -o "$ARTIFACTS_FILE"
        AGENT_URL=$(grep "^wazuh_agent_${ARCH}_${PKG_TYPE}:" "$ARTIFACTS_FILE" | sed 's/^[^"]*"//;s/"$//')
        if [[ -z "$AGENT_URL" ]]; then
            echo "[ERROR] 'wazuh_agent_${ARCH}_${PKG_TYPE}' key not found in artifacts YAML." >&2
            exit 1
        fi
        AGENT_PKG="$WORKDIR/$(basename "$AGENT_URL")"
        echo "[INFO] Downloading agent package: $AGENT_URL"
        curl -sS --fail -L "$AGENT_URL" -o "$AGENT_PKG"
        echo "[INFO] Installing agent (WAZUH_MANAGER=$MANAGER)"
        if [[ "$PKG_TYPE" == "deb" ]]; then
            WAZUH_MANAGER="$MANAGER" dpkg -i "$AGENT_PKG"
        else
            WAZUH_MANAGER="$MANAGER" rpm -ivh "$AGENT_PKG"
        fi
        ;;
    4.*)
        # GA: install from the official 4.x package repository (auto-resolves latest 4.x).
        echo "[INFO] Configuring the Wazuh 4.x package repository"
        if [[ "$PKG_TYPE" == "deb" ]]; then
            curl -sS --fail https://packages.wazuh.com/key/GPG-KEY-WAZUH \
                | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
            chmod 644 /usr/share/keyrings/wazuh.gpg
            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
                > /etc/apt/sources.list.d/wazuh.list
            apt-get update -y
            echo "[INFO] Installing agent (WAZUH_MANAGER=$MANAGER)"
            WAZUH_MANAGER="$MANAGER" apt-get install -y wazuh-agent
        else
            rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
            cat > /etc/yum.repos.d/wazuh.repo <<'REPO'
[wazuh]
gpgcheck=1
gpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH
enabled=1
name=EL-$releasever - Wazuh
baseurl=https://packages.wazuh.com/4.x/yum/
protect=1
REPO
            echo "[INFO] Installing agent (WAZUH_MANAGER=$MANAGER)"
            WAZUH_MANAGER="$MANAGER" yum install -y wazuh-agent
        fi
        ;;
    *)
        echo "[ERROR] Unsupported version '$VERSION' (expected 4.x or 5.x)." >&2
        exit 1
        ;;
esac

# --- Configure the FIM + Logcollector load paths -----------------------------
mkdir -p "$FIM_DIR" "$(dirname "$LOG_FILE")"
echo "[INFO] Appending perf FIM/Logcollector config to /var/ossec/etc/ossec.conf"
cat >> /var/ossec/etc/ossec.conf <<EOF

<!-- Added by tools/performance/scripts/setup-agent.sh -->
<ossec_config>
  <syscheck>
    <directories check_all="yes" realtime="yes">$FIM_DIR</directories>
  </syscheck>
  <localfile>
    <log_format>syslog</log_format>
    <location>$LOG_FILE</location>
  </localfile>
</ossec_config>
EOF

systemctl daemon-reload
systemctl enable wazuh-agent
systemctl restart wazuh-agent

echo "[INFO] Agent enrolled and watching FIM=$FIM_DIR LOG=$LOG_FILE"
echo "[INFO] Start the load loop with: ./agent-load.sh --fim-dir $FIM_DIR --log-file $LOG_FILE --duration 3600"
