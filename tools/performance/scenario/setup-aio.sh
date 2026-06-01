#!/bin/bash
#
# setup-aio.sh — install a Wazuh AIO (manager + indexer + dashboard) on this host
# using the official nightly artifacts + installation assistant, downloaded via
# curl from the staging repository. No dependency on any local provisioning script.
#
# Run as root on the target AIO host (16 GB RAM / 8 vCPU for the perf scenario).
#
set -e

ARTIFACTS_URL="https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/artifact-urls/artifact_urls_5.0.0-latest.yaml"
PASSWORD_OUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --artifacts-url) ARTIFACTS_URL="$2"; shift 2 ;;
        --password-out)  PASSWORD_OUT="$2"; shift 2 ;;
        *) echo "Usage: $0 [--artifacts-url URL] [--password-out FILE]"; exit 1 ;;
    esac
done

# --- Detect architecture & package type (matches the official key naming) ----
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
echo "[INFO] Architecture: $ARCH | Package type: $PKG_TYPE"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
ARTIFACTS_FILE="$WORKDIR/artifact_urls.yaml"

echo "[INFO] Downloading artifacts YAML: $ARTIFACTS_URL"
curl -sS --fail -L "$ARTIFACTS_URL" -o "$ARTIFACTS_FILE"

# Extract a URL value from the artifacts YAML by key (empty if absent).
get_artifact_url() {
    grep "^${1}:" "$ARTIFACTS_FILE" | sed 's/^[^"]*"//;s/"$//'
}

# --- Run the official installation assistant in AIO mode ---------------------
INSTALL_URL=$(get_artifact_url "wazuh_installation_assistant")
if [[ -z "$INSTALL_URL" ]]; then
    echo "[ERROR] 'wazuh_installation_assistant' key not found in artifacts YAML." >&2
    exit 1
fi
INSTALL_SCRIPT="$WORKDIR/$(basename "$INSTALL_URL")"

echo "[INFO] Downloading installation assistant: $INSTALL_URL"
curl -sS --fail -L "$INSTALL_URL" -o "$INSTALL_SCRIPT"

echo "[INFO] Running: bash $INSTALL_SCRIPT -a -d local -id"
bash "$INSTALL_SCRIPT" -a -d local -id

# --- Best-effort: capture the generated admin password for the sampler -------
# The assistant writes credentials to wazuh-passwords.txt inside the install
# files tarball. This is best-effort; if it fails, read it manually and pass
# --password to run-scenario.sh / run-test.sh.
if [[ -n "$PASSWORD_OUT" ]]; then
    TARBALL="wazuh-install-files.tar"
    if [[ -f "$TARBALL" ]]; then
        mkdir -p "$(dirname "$PASSWORD_OUT")"
        if tar -xOf "$TARBALL" wazuh-install-files/wazuh-passwords.txt 2>/dev/null \
            | grep -A1 "indexer_username: 'admin'" \
            | grep -oP "indexer_password: '\K[^']+" \
            | head -1 > "$PASSWORD_OUT" && [[ -s "$PASSWORD_OUT" ]]; then
            chmod 600 "$PASSWORD_OUT"
            echo "[INFO] Wrote admin indexer password to $PASSWORD_OUT"
        else
            rm -f "$PASSWORD_OUT"
            echo "[WARN] Could not extract admin password — read wazuh-passwords.txt manually."
        fi
    fi
fi

# --- Print agent enrollment instructions -------------------------------------
AGENT_URL=$(get_artifact_url "wazuh_agent_${ARCH}_${PKG_TYPE}")
IP=$(hostname -I | awk '{print $1}')

echo
echo "======================================================"
echo " WAZUH AIO INSTALL COMPLETE"
echo " Dashboard: https://${IP}"
echo "======================================================"
echo
echo "[INFO] Enroll each agent host with:"
echo "  ./setup-agent.sh --manager ${IP} --artifacts-url ${ARTIFACTS_URL}"
echo "[INFO] (agent package: ${AGENT_URL:-<not in YAML>})"
