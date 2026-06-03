#!/bin/bash
#
# setup-indexer.sh — install a single standalone Wazuh INDEXER node (no manager,
# no dashboard) on this host, via the official installation assistant. Used by
# Tracks B and C, which benchmark the indexer in isolation.
#
# A single --version flag selects the source (same as setup-aio.sh):
#   - 5.x  → latest staging nightly (resolved from the artifacts YAML)
#   - 4.x  → GA installer from packages.wazuh.com
#
#   sudo ./setup-indexer.sh --version 5.0.0
#   sudo ./setup-indexer.sh --version 4.14
#
# Run as root. Leaves a single-node indexer reachable on https://<host>:9200.
#
set -e

VERSION="5.0.0"
NODE_NAME="node-1"
PASSWORD_OUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)      VERSION="$2"; shift 2 ;;
        --node-name)    NODE_NAME="$2"; shift 2 ;;
        --password-out) PASSWORD_OUT="$2"; shift 2 ;;
        *) echo "Usage: $0 [--version X.Y.Z] [--node-name NAME] [--password-out FILE]"; exit 1 ;;
    esac
done

echo "[INFO] Version: $VERSION | Node: $NODE_NAME"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
INSTALL_SCRIPT="$WORKDIR/wazuh-install.sh"

# --- Resolve the installer for the requested version (mirrors setup-aio.sh) ---
case "$VERSION" in
    5.*)
        ARTIFACTS_URL="https://packages-staging.xdrsiem.wazuh.info/nightly/${VERSION}/artifact-urls/artifact_urls_${VERSION}-latest.yaml"
        ARTIFACTS_FILE="$WORKDIR/artifact_urls.yaml"
        echo "[INFO] Downloading artifacts YAML: $ARTIFACTS_URL"
        curl -sS --fail -L "$ARTIFACTS_URL" -o "$ARTIFACTS_FILE"
        INSTALL_URL=$(grep "^wazuh_installation_assistant:" "$ARTIFACTS_FILE" | sed 's/^[^"]*"//;s/"$//')
        if [[ -z "$INSTALL_URL" ]]; then
            echo "[ERROR] 'wazuh_installation_assistant' key not found in artifacts YAML." >&2
            exit 1
        fi
        ;;
    4.*)
        MAJOR_MINOR=$(echo "$VERSION" | cut -d. -f1-2)
        INSTALL_URL="https://packages.wazuh.com/${MAJOR_MINOR}/wazuh-install.sh"
        ;;
    *)
        echo "[ERROR] Unsupported version '$VERSION' (expected 4.x or 5.x)." >&2
        exit 1
        ;;
esac

echo "[INFO] Downloading installer: $INSTALL_URL"
curl -sS --fail -L "$INSTALL_URL" -o "$INSTALL_SCRIPT"

# --- Single-indexer config (no server / no dashboard) ------------------------
IP=$(hostname -I | awk '{print $1}')
cat > "$WORKDIR/config.yml" <<EOF
nodes:
  indexer:
    - name: ${NODE_NAME}
      ip: "${IP}"
EOF

# The assistant reads config.yml from its CWD and leaves wazuh-install-files.tar there.
cd "$WORKDIR"
INSTALL_LOG="$WORKDIR/install.log"
set -o pipefail
echo "[INFO] Generating config + certificates"
bash "$INSTALL_SCRIPT" --generate-config-files 2>&1 | tee "$INSTALL_LOG"
echo "[INFO] Installing the Wazuh indexer node '${NODE_NAME}'"
bash "$INSTALL_SCRIPT" --wazuh-indexer "${NODE_NAME}" 2>&1 | tee -a "$INSTALL_LOG"
echo "[INFO] Initializing the cluster (security)"
bash "$INSTALL_SCRIPT" --start-cluster 2>&1 | tee -a "$INSTALL_LOG"
set +o pipefail

# --- Capture the admin password for the sampler -----------------------------
# Primary: the assistant prints it ("Password: ..."); fallback: wazuh-passwords.txt
# inside wazuh-install-files.tar (located anywhere on disk).
if [[ -n "$PASSWORD_OUT" ]]; then
    PW=""
    # Anchor on the "User: admin" → next "Password: <pw>" pair (the log has other
    # Password: lines). Strip ANSI colors first, then trim.
    [[ -f "$INSTALL_LOG" ]] && PW=$(sed -E 's/\x1b\[[0-9;]*m//g' "$INSTALL_LOG" \
        | awk '/User:[[:space:]]*admin/{u=1;next} u&&/Password:/{sub(/.*Password:[[:space:]]*/,"");print;exit}' \
        | sed -E 's/^[[:space:]]+//; s/[[:space:]]+$//' | tr -d '\r')
    if [[ -z "$PW" ]]; then
        TARBALL=$(find / -name wazuh-install-files.tar -type f 2>/dev/null | head -1)
        if [[ -n "$TARBALL" ]]; then
            EXDIR=$(mktemp -d)
            tar -xf "$TARBALL" -C "$EXDIR" 2>/dev/null || true
            PWFILE=$(find "$EXDIR" -name wazuh-passwords.txt -type f 2>/dev/null | head -1)
            [[ -n "$PWFILE" ]] && PW=$(awk -F"'" '/indexer_username: .admin.$/{f=1} f && /indexer_password:/{print $2; exit}' "$PWFILE")
            rm -rf "$EXDIR"
        fi
    fi
    if [[ -n "$PW" ]]; then
        mkdir -p "$(dirname "$PASSWORD_OUT")"
        printf '%s' "$PW" > "$PASSWORD_OUT"
        chmod 600 "$PASSWORD_OUT"
        echo "[INFO] Wrote admin indexer password to $PASSWORD_OUT"
    else
        echo "[WARN] Could not capture admin password; read it from the install summary above." >&2
    fi
fi

echo
echo "======================================================"
echo " WAZUH INDEXER (single node) READY — version: $VERSION"
echo " Endpoint: https://${IP}:9200"
echo "======================================================"
echo "[INFO] Verify: curl -k -u admin:<pass> https://${IP}:9200/_cluster/health?pretty"
