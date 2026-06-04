#!/bin/bash
#
# setup-aio.sh — install a Wazuh AIO (manager + indexer + dashboard) on this host
# from the official installation assistant, downloaded via curl.
#
# A single --version flag selects the source; the flow is identical for both:
#   - 5.x  → latest staging nightly (resolved from the artifacts YAML)
#   - 4.x  → GA installer from packages.wazuh.com
#
#   sudo ./setup-aio.sh --version 5.0
#   sudo ./setup-aio.sh --version 4.14
#
# Versions are given as MAJOR.MINOR (e.g. 5.0, 4.14): the latest patch of that line
# is installed, and the run is labeled with the resolved patch.
#
# Run as root on the target AIO host (16 GB RAM / 8 vCPU for the perf scenario).
#
set -e

VERSION="5.0"
PASSWORD_OUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)      VERSION="$2"; shift 2 ;;
        --password-out) PASSWORD_OUT="$2"; shift 2 ;;
        *) echo "Usage: $0 [--version MAJOR.MINOR] [--password-out FILE]"; exit 1 ;;
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
echo "[INFO] Version: $VERSION | Architecture: $ARCH | Package type: $PKG_TYPE"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
INSTALL_SCRIPT="$WORKDIR/wazuh-install.sh"

# --- Resolve the installer for the requested version -------------------------
case "$VERSION" in
    5.*)
        # Staging nightly: the assistant URL lives in the artifacts YAML, published per
        # exact patch. Resolve the MAJOR.MINOR input to that patch (pre-release 5.x → .0,
        # e.g. 5.0 → 5.0.0); a full MAJOR.MINOR.PATCH passes through unchanged.
        STAGING_VERSION="$VERSION"
        [[ "$STAGING_VERSION" == *.*.* ]] || STAGING_VERSION="${STAGING_VERSION}.0"
        ARTIFACTS_URL="https://packages-staging.xdrsiem.wazuh.info/nightly/${STAGING_VERSION}/artifact-urls/artifact_urls_${STAGING_VERSION}-latest.yaml"
        ARTIFACTS_FILE="$WORKDIR/artifact_urls.yaml"
        echo "[INFO] Downloading artifacts YAML: $ARTIFACTS_URL"
        curl -sS --fail -L "$ARTIFACTS_URL" -o "$ARTIFACTS_FILE"
        INSTALL_URL=$(grep "^wazuh_installation_assistant:" "$ARTIFACTS_FILE" | sed 's/^[^"]*"//;s/"$//')
        if [[ -z "$INSTALL_URL" ]]; then
            echo "[ERROR] 'wazuh_installation_assistant' key not found in artifacts YAML." >&2
            exit 1
        fi
        INSTALLER_ARGS="-a -d local -id"
        ;;
    4.*)
        # GA: stable public installer at packages.wazuh.com/<major.minor>/.
        MAJOR_MINOR=$(echo "$VERSION" | cut -d. -f1-2)
        INSTALL_URL="https://packages.wazuh.com/${MAJOR_MINOR}/wazuh-install.sh"
        INSTALLER_ARGS="-a"
        ;;
    *)
        echo "[ERROR] Unsupported version '$VERSION' (expected 4.x or 5.x)." >&2
        exit 1
        ;;
esac

echo "[INFO] Downloading installer: $INSTALL_URL"
curl -sS --fail -L "$INSTALL_URL" -o "$INSTALL_SCRIPT"

# shellcheck disable=SC2086  # INSTALLER_ARGS is intentionally word-split
echo "[INFO] Running: bash $INSTALL_SCRIPT $INSTALLER_ARGS"
INSTALL_LOG="$WORKDIR/install.log"
set -o pipefail
bash "$INSTALL_SCRIPT" $INSTALLER_ARGS 2>&1 | tee "$INSTALL_LOG"
set +o pipefail

# --- Capture the admin password for the sampler -----------------------------
# Primary: the assistant prints it in its summary ("Password: ..."); this covers
# the dev/staging default (admin) and GA's generated value alike. Fallback: parse
# wazuh-passwords.txt from wazuh-install-files.tar (located anywhere on disk).
if [[ -n "$PASSWORD_OUT" ]]; then
    PW=""
    # The summary prints "User: admin" then "Password: <pw>" — anchor on that pair
    # (the log has other Password: lines). Strip ANSI colors first, then trim.
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

# --- Print agent enrollment instructions -------------------------------------
IP=$(hostname -I | awk '{print $1}')

echo
echo "======================================================"
echo " WAZUH AIO INSTALL COMPLETE (version: $VERSION)"
echo " Dashboard: https://${IP}"
echo "======================================================"
echo
echo "[INFO] Enroll each agent host with:"
echo "  ./setup-agent.sh --version ${VERSION} --manager ${IP}"
