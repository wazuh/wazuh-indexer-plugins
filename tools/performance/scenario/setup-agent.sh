#!/bin/bash
#
# setup-agent.sh — install + enroll a Wazuh agent (beta2) from the official
# nightly artifacts, and configure it to watch the FIM + Logcollector load paths
# used by the performance scenario. Downloads the package via curl; no dependency
# on any local provisioning script.
#
# Run as root on each agent host, pointing at the AIO manager IP.
#
set -e

ARTIFACTS_URL="https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/artifact-urls/artifact_urls_5.0.0-latest.yaml"
MANAGER=""
FIM_DIR="/var/perf-fim"
LOG_FILE="/var/perf-logs/load.log"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --manager)       MANAGER="$2"; shift 2 ;;
        --artifacts-url) ARTIFACTS_URL="$2"; shift 2 ;;
        --fim-dir)       FIM_DIR="$2"; shift 2 ;;
        --log-file)      LOG_FILE="$2"; shift 2 ;;
        *) echo "Usage: $0 --manager IP [--artifacts-url URL] [--fim-dir D] [--log-file F]"; exit 1 ;;
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
echo "[INFO] Architecture: $ARCH | Package type: $PKG_TYPE | Manager: $MANAGER"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
ARTIFACTS_FILE="$WORKDIR/artifact_urls.yaml"

echo "[INFO] Downloading artifacts YAML: $ARTIFACTS_URL"
curl -sS --fail -L "$ARTIFACTS_URL" -o "$ARTIFACTS_FILE"

get_artifact_url() {
    grep "^${1}:" "$ARTIFACTS_FILE" | sed 's/^[^"]*"//;s/"$//'
}

AGENT_URL=$(get_artifact_url "wazuh_agent_${ARCH}_${PKG_TYPE}")
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

# --- Configure the FIM + Logcollector load paths -----------------------------
mkdir -p "$FIM_DIR" "$(dirname "$LOG_FILE")"
echo "[INFO] Appending perf FIM/Logcollector config to /var/ossec/etc/ossec.conf"
cat >> /var/ossec/etc/ossec.conf <<EOF

<!-- Added by tools/performance/scenario/setup-agent.sh -->
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
