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
#   sudo ./setup-aio.sh --version 5.0 --package ./wazuh-indexer_5.0.0_amd64.deb
#
# Versions are given as MAJOR.MINOR (e.g. 5.0, 4.14): the latest patch of that line
# is installed, and the run is labeled with the resolved patch.
#
# --package installs the AIO normally, then overwrites ONLY the wazuh-indexer package
# with the given local .deb/.rpm — keeping the assistant's generated admin password,
# security index and demo certs — so the AIO runs a specific indexer build.
#
# Run as root on the target AIO host (16 GB RAM / 8 vCPU for the perf scenario).
#
set -e

VERSION="5.0"
PASSWORD_OUT=""
PACKAGE=""           # after the AIO install, overwrite the wazuh-indexer package with this
TUNE_CONFIG=""       # perf-tune YAML; empty → perf-tune-indexer.sh built-in default
ARTIFACT_URL=""      # TEMP workaround: KEY=URL to inject into the assistant's artifacts YAML

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)      VERSION="$2"; shift 2 ;;
        --password-out) PASSWORD_OUT="$2"; shift 2 ;;
        --package)      PACKAGE="$2"; shift 2 ;;
        --tune-config)  TUNE_CONFIG="$2"; shift 2 ;;
        --artifact-url) ARTIFACT_URL="$2"; shift 2 ;;
        *) echo "Usage: $0 [--version MAJOR.MINOR] [--password-out FILE] [--package FILE] [--tune-config perf-tune.yml] [--artifact-url KEY=URL]"; exit 1 ;;
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

# Validate the override up front so a bad path fails before the long assistant install.
# --package accepts a local .deb/.rpm OR an http(s) URL (e.g. a nightly-backup build).
if [[ -n "$PACKAGE" ]]; then
    if [[ "$PACKAGE" != http*://* && ! -f "$PACKAGE" ]]; then
        echo "[ERROR] --package file not found: $PACKAGE" >&2
        exit 1
    fi
    echo "[INFO] Will overwrite the wazuh-indexer package post-install with: $PACKAGE"
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT
INSTALL_SCRIPT="$WORKDIR/wazuh-install.sh"

# A --package URL is downloaded once here so the overwrite step can treat it as a local file.
if [[ "$PACKAGE" == http*://* ]]; then
    echo "[INFO] Downloading --package URL: $PACKAGE"
    PKG_DL="$WORKDIR/$(basename "$PACKAGE")"
    curl -sS --fail -L "$PACKAGE" -o "$PKG_DL"
    PACKAGE="$PKG_DL"
fi

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

# TEMP workaround — inject a missing artifacts-YAML key (broken nightly build). The
# assistant downloads its own copy of artifact_urls*.yaml and aborts on a missing key, so
# we put a `curl` shim on PATH for the assistant run that appends KEY=URL to any
# artifact_urls YAML it fetches. Remove by dropping --artifact-url.
RUN_PATH="$PATH"
if [[ -n "$ARTIFACT_URL" ]]; then
    AKEY="${ARTIFACT_URL%%=*}"; AURL="${ARTIFACT_URL#*=}"
    if [[ -z "$AKEY" || "$AKEY" == "$ARTIFACT_URL" || -z "$AURL" ]]; then
        echo "[ERROR] --artifact-url must be KEY=URL (e.g. wazuh_indexer_amd64_deb=https://...)." >&2
        exit 1
    fi
    SHIM_DIR="$WORKDIR/shim"; mkdir -p "$SHIM_DIR"
    REAL_CURL="$(command -v curl)"
    cat > "$SHIM_DIR/curl" <<'SHIM'
#!/bin/bash
# TEMP curl shim: append a missing key to any artifacts YAML the assistant downloads.
real='__REAL_CURL__'; key='__KEY__'; url='__URL__'
inject() { if ! grep -q "$key" "$1" 2>/dev/null; then printf '%s: "%s"\n' "$key" "$url" >> "$1"; echo "[INFO] (TEMP) injected artifact key '$key' into $1" >&2; fi; }
out=""; prev=""
for a in "$@"; do [[ "$prev" == "-o" || "$prev" == "--output" ]] && out="$a"; prev="$a"; done
case "$*" in
  *artifact_urls*)
    if [[ -n "$out" ]]; then "$real" "$@"; rc=$?; [[ -f "$out" ]] && inject "$out"; exit "$rc"
    else tmp="$(mktemp)"; "$real" "$@" >"$tmp"; rc=$?; inject "$tmp"; cat "$tmp"; rm -f "$tmp"; exit "$rc"; fi ;;
esac
exec "$real" "$@"
SHIM
    sed -i "s#__REAL_CURL__#${REAL_CURL}#; s#__KEY__#${AKEY}#; s#__URL__#${AURL}#" "$SHIM_DIR/curl"
    chmod +x "$SHIM_DIR/curl"
    RUN_PATH="$SHIM_DIR:$PATH"
    echo "[INFO] (TEMP) Will inject artifact key '$AKEY' → '$AURL' into the assistant's YAML."
fi

# shellcheck disable=SC2086  # INSTALLER_ARGS is intentionally word-split
echo "[INFO] Running: bash $INSTALL_SCRIPT $INSTALLER_ARGS"
INSTALL_LOG="$WORKDIR/install.log"
set -o pipefail
PATH="$RUN_PATH" bash "$INSTALL_SCRIPT" $INSTALLER_ARGS 2>&1 | tee "$INSTALL_LOG"
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

# --- Overwrite ONLY the wazuh-indexer package with a local build (optional) ---
# The AIO is already installed and its generated admin password captured above. Replace
# just the wazuh-indexer package, KEEPING the assistant's config/certs/security index:
#   - do NOT export GENERATE_CERTS  → the postinst won't regenerate demo certs
#   - do NOT run indexer-security-init.sh → keeps the captured (random) admin password
#   - keep the existing opensearch.yml via the package manager's conffile flags
# Certs (/etc/wazuh-indexer/certs) and data (/var/lib/wazuh-indexer) are not package
# files, so a replace leaves them untouched.
if [[ -n "$PACKAGE" ]]; then
    echo
    echo "[INFO] Overwriting the wazuh-indexer package with local build: $PACKAGE"
    systemctl stop wazuh-indexer
    if [[ "$PKG_TYPE" == "deb" ]]; then
        # --force-confold keeps the AIO's opensearch.yml; --force-downgrade allows a
        # same/older build; apt-get -f repairs any unmet deps a bare dpkg -i would leave.
        dpkg -i --force-confold --force-downgrade "$PACKAGE" || apt-get install -y -f
    else
        # --oldpackage permits downgrade/same-version; --force reinstalls over an identical
        # version; %config(noreplace) files (opensearch.yml) are preserved (new one → .rpmnew).
        rpm -Uvh --force --oldpackage "$PACKAGE"
    fi
    systemctl daemon-reload
    echo "[INFO] Starting wazuh-indexer (custom build)"
    systemctl start wazuh-indexer

    echo "[INFO] Waiting for the indexer HTTP port to accept connections ..."
    for _ in $(seq 1 60); do
        code=$(curl -ks -o /dev/null -w '%{http_code}' https://localhost:9200 2>/dev/null || echo 000)
        [[ "$code" != "000" ]] && break
        sleep 5
    done
    echo "[INFO] wazuh-indexer overwrite complete; AIO security state (password/certs) preserved."
fi

# Apply perf-test tuning (heap + optional toggles) from the YAML config and restart the
# indexer once. Shared with setup-indexer.sh so both scenarios measure the same config.
# See config/perf-tune.yml.
bash "$(dirname "$0")/perf-tune-indexer.sh" "$VERSION" ${TUNE_CONFIG:+"$TUNE_CONFIG"}
