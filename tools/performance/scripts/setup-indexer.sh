#!/bin/bash
#
# setup-indexer.sh — install a single standalone Wazuh INDEXER node (no manager,
# no dashboard) on this host. Used by the `isolated` performance scenario to
# benchmark the indexer alone. Run as root.
#
# Both versions install the wazuh-indexer PACKAGE directly (no installation
# assistant) and end up with the demo admin/admin credentials. They differ only in
# how the certificates are produced:
#   - 5.x → install with GENERATE_CERTS=true; the package postinst generates the demo
#           certificates itself (root CA + admin + node cert).
#   - 4.x → the package has no GENERATE_CERTS, so certificates are generated with the
#           official wazuh-certs-tool and deployed manually (the documented
#           "step-by-step" install).
# Both then bind 0.0.0.0 and initialize the security index with indexer-security-init.sh.
#
#   sudo ./setup-indexer.sh --version 5.0
#   sudo ./setup-indexer.sh --version 4.14
#
# Versions are given as MAJOR.MINOR (e.g. 5.0, 4.14): the latest patch of that line
# is installed.
#
# Leaves a single-node indexer reachable on https://<host>:9200 with admin/admin.
#
set -e

VERSION="5.0"
NODE_NAME="node-1"   # the package's default node.name / nodes_dn — keep it
PASSWORD_OUT=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --version)      VERSION="$2"; shift 2 ;;
        --node-name)    NODE_NAME="$2"; shift 2 ;;
        --password-out) PASSWORD_OUT="$2"; shift 2 ;;
        *) echo "Usage: $0 [--version MAJOR.MINOR] [--node-name NAME] [--password-out FILE]"; exit 1 ;;
    esac
done

echo "[INFO] Version: $VERSION | Node: $NODE_NAME"

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

case "$VERSION" in
    5.*)
        # --- 5.x: package + self-generated demo certs (GENERATE_CERTS=true) ------
        # Detect arch & package type to match the artifact key naming (as setup-agent.sh).
        ARCH=$(uname -m)
        if command -v dpkg >/dev/null 2>&1; then
            PKG_TYPE="deb"
            case "$ARCH" in x86_64) ARCH="amd64" ;; aarch64) ARCH="arm64" ;; esac
        elif command -v rpm >/dev/null 2>&1; then
            PKG_TYPE="rpm"
            case "$ARCH" in amd64) ARCH="x86_64" ;; arm64) ARCH="aarch64" ;; esac
        else
            echo "[ERROR] Neither dpkg nor rpm found — cannot install." >&2
            exit 1
        fi

        # Staging nightly is published per exact patch; resolve the MAJOR.MINOR input
        # to that patch (pre-release 5.x → .0, e.g. 5.0 → 5.0.0). A full patch passes through.
        STAGING_VERSION="$VERSION"
        [[ "$STAGING_VERSION" == *.*.* ]] || STAGING_VERSION="${STAGING_VERSION}.0"
        ARTIFACTS_URL="https://packages-staging.xdrsiem.wazuh.info/nightly/${STAGING_VERSION}/artifact-urls/artifact_urls_${STAGING_VERSION}-latest.yaml"
        echo "[INFO] Downloading artifacts YAML: $ARTIFACTS_URL"
        curl -sS --fail -L "$ARTIFACTS_URL" -o "$WORKDIR/artifact_urls.yaml"
        PKG_URL=$(grep "^wazuh_indexer_${ARCH}_${PKG_TYPE}:" "$WORKDIR/artifact_urls.yaml" | sed 's/^[^"]*"//;s/"$//')
        if [[ -z "$PKG_URL" ]]; then
            echo "[ERROR] 'wazuh_indexer_${ARCH}_${PKG_TYPE}' key not found in artifacts YAML." >&2
            exit 1
        fi
        PKG="$WORKDIR/$(basename "$PKG_URL")"
        echo "[INFO] Downloading indexer package: $PKG_URL"
        curl -sS --fail -L "$PKG_URL" -o "$PKG"

        # GENERATE_CERTS=true → the postinst runs install-demo-certificates.sh, producing
        # a root CA + admin + node cert (SAN localhost/127.0.0.1) in /etc/wazuh-indexer/certs.
        echo "[INFO] Installing wazuh-indexer with self-generated demo certs (GENERATE_CERTS=true)"
        if [[ "$PKG_TYPE" == "deb" ]]; then
            # Re-run dpkg -i after -f so the postinst runs once more WITH GENERATE_CERTS
            # set (the -f pass would otherwise configure it without the variable).
            GENERATE_CERTS=true dpkg -i "$PKG" || { apt-get install -y -f; GENERATE_CERTS=true dpkg -i "$PKG"; }
        else
            GENERATE_CERTS=true rpm -ivh "$PKG"
        fi
        ;;
    4.*)
        # --- 4.x: package from the GA repo + manual certs (step-by-step install) --
        MAJOR_MINOR=$(echo "$VERSION" | cut -d. -f1-2)

        if command -v dpkg >/dev/null 2>&1; then
            echo "[INFO] Configuring the Wazuh 4.x apt repository"
            curl -sS --fail https://packages.wazuh.com/key/GPG-KEY-WAZUH \
                | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import
            chmod 644 /usr/share/keyrings/wazuh.gpg
            echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" \
                > /etc/apt/sources.list.d/wazuh.list
            apt-get update -y
            echo "[INFO] Installing wazuh-indexer"
            apt-get install -y wazuh-indexer
        else
            echo "[INFO] Configuring the Wazuh 4.x yum repository"
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
            echo "[INFO] Installing wazuh-indexer"
            yum install -y wazuh-indexer
        fi

        # Generate node + admin certs with the official tool (no assistant). The node is
        # named ${NODE_NAME} (= the package's default node.name / nodes_dn). The cert IP is
        # 127.0.0.1 so securityadmin — which connects locally — validates the node cert;
        # the monitor connects with insecure TLS, so it doesn't need the private IP in SAN.
        echo "[INFO] Generating certificates with wazuh-certs-tool"
        cd "$WORKDIR"
        curl -sS --fail -L "https://packages.wazuh.com/${MAJOR_MINOR}/wazuh-certs-tool.sh" -o wazuh-certs-tool.sh
        cat > config.yml <<EOF
nodes:
  indexer:
    - name: ${NODE_NAME}
      ip: "127.0.0.1"
EOF
        bash ./wazuh-certs-tool.sh -A
        tar -cf ./wazuh-certificates.tar -C ./wazuh-certificates/ .

        echo "[INFO] Deploying certificates to /etc/wazuh-indexer/certs"
        mkdir -p /etc/wazuh-indexer/certs
        tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ \
            "./${NODE_NAME}.pem" "./${NODE_NAME}-key.pem" ./admin.pem ./admin-key.pem ./root-ca.pem
        mv -n "/etc/wazuh-indexer/certs/${NODE_NAME}.pem"     /etc/wazuh-indexer/certs/indexer.pem
        mv -n "/etc/wazuh-indexer/certs/${NODE_NAME}-key.pem" /etc/wazuh-indexer/certs/indexer-key.pem
        chmod 500 /etc/wazuh-indexer/certs
        chmod 400 /etc/wazuh-indexer/certs/*
        chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
        ;;
    *)
        echo "[ERROR] Unsupported version '$VERSION' (expected 4.x or 5.x)." >&2
        exit 1
        ;;
esac

# --- Bind on all interfaces (shared) ----------------------------------------
# Make the node reachable both locally (health checks / securityadmin via 127.0.0.1)
# and over the private network the monitor/sampler use. indexer-security-init.sh maps
# network.host 0.0.0.0 → 127.0.0.1, which both versions' node certs cover.
CONF=/etc/wazuh-indexer/opensearch.yml
if grep -qE '^[[:space:]]*network\.host:' "$CONF"; then
    sed -i -E 's/^([[:space:]]*network\.host:).*/\1 0.0.0.0/' "$CONF"
else
    echo 'network.host: 0.0.0.0' >> "$CONF"
fi

# --- Start + initialize the security index (shared) -------------------------
systemctl daemon-reload
systemctl enable wazuh-indexer >/dev/null 2>&1 || true
echo "[INFO] Starting wazuh-indexer"
systemctl start wazuh-indexer

echo "[INFO] Waiting for the indexer HTTP port to accept connections ..."
for _ in $(seq 1 60); do
    code=$(curl -ks -o /dev/null -w '%{http_code}' https://localhost:9200 2>/dev/null || echo 000)
    [[ "$code" != "000" ]] && break
    sleep 5
done

echo "[INFO] Initializing the indexer security index"
bash /usr/share/wazuh-indexer/bin/indexer-security-init.sh \
    || echo "[WARN] indexer-security-init.sh returned non-zero; check the indexer logs." >&2

PW="admin"   # both paths use the demo security config (admin/admin)

# --- Persist the admin password for the sampler -----------------------------
if [[ -n "$PASSWORD_OUT" ]]; then
    mkdir -p "$(dirname "$PASSWORD_OUT")"
    printf '%s' "$PW" > "$PASSWORD_OUT"
    chmod 600 "$PASSWORD_OUT"
    echo "[INFO] Wrote admin indexer password to $PASSWORD_OUT"
fi

IP=$(hostname -I | awk '{print $1}')
echo
echo "======================================================"
echo " WAZUH INDEXER (single node) READY — version: $VERSION"
echo " Endpoint: https://${IP}:9200  (admin/admin)"
echo "======================================================"
echo "[INFO] Verify: curl -k -u admin:admin https://${IP}:9200/_cluster/health?pretty"
