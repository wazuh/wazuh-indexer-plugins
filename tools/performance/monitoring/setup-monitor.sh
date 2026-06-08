#!/bin/bash
#
# setup-monitor.sh — bring up the Prometheus + Grafana monitor stack (Tracks B/C)
# on the dedicated monitor host, scraping node_exporter on the indexer host.
#
#   sudo ./setup-monitor.sh --indexer-host <indexer-ip>
#
# Requires Docker + the Compose plugin (installed if missing on apt hosts).
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
INDEXER_HOST=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --indexer-host) INDEXER_HOST="$2"; shift 2 ;;
        *) echo "Usage: $0 --indexer-host <indexer-ip>"; exit 1 ;;
    esac
done

if [[ -z "$INDEXER_HOST" ]]; then
    echo "[ERROR] --indexer-host <indexer-ip> is required." >&2
    exit 1
fi

if ! command -v docker >/dev/null 2>&1; then
    echo "[INFO] Installing Docker"
    curl -sSL https://get.docker.com | sh
fi

# Render the scrape config with the indexer host, then start the stack.
sed "s/\${INDEXER_HOST}/${INDEXER_HOST}/g" "$SCRIPT_DIR/prometheus.yml" \
    > "$SCRIPT_DIR/prometheus.rendered.yml"

echo "[INFO] Starting Prometheus + Grafana (scraping ${INDEXER_HOST}:9100)"
docker compose -f "$SCRIPT_DIR/compose.yml" up -d

IP=$(hostname -I | awk '{print $1}')
echo
echo "======================================================"
echo " MONITOR STACK UP"
echo " Prometheus: http://${IP}:9090"
echo " Grafana:    http://${IP}:3000  (admin / admin)"
echo "======================================================"
