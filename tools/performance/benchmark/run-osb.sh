#!/bin/bash
#
# run-osb.sh — run the custom Wazuh OpenSearch Benchmark workload (Track B).
#
# Generates the corpus first (benchmark/gen-corpora.py) if it is missing, runs
# the benchmark against an isolated indexer, and captures the same per-minute
# metric series via metrics/sampler.py for the duration of the test.
#
# Prereq: pip install opensearch-benchmark
#
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
WORKLOAD_DIR="$SCRIPT_DIR/workloads/wazuh-events"
SAMPLER="$SCRIPT_DIR/../metrics/sampler.py"

TARGET="https://localhost:9200"
USER="admin"
PASSWORD="admin"
DOCS=1000000
OUT="./runs/osb-$(date +%Y%m%d-%H%M%S)"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)   TARGET="$2"; shift 2 ;;
        --user)     USER="$2"; shift 2 ;;
        --password) PASSWORD="$2"; shift 2 ;;
        --docs)     DOCS="$2"; shift 2 ;;
        --out)      OUT="$2"; shift 2 ;;
        *) echo "Usage: $0 [--target URL] [--user U] [--password P] [--docs N] [--out DIR]"; exit 1 ;;
    esac
done

mkdir -p "$OUT"

if [[ ! -f "$WORKLOAD_DIR/documents.json" ]]; then
    echo "[INFO] Corpus missing — generating $DOCS documents..."
    python3 "$SCRIPT_DIR/gen-corpora.py" --docs "$DOCS"
fi

# Strip scheme for OSB --target-hosts and pass TLS/auth via client options.
HOST="${TARGET#https://}"; HOST="${HOST#http://}"

# Sample cluster internals for ~10 min alongside the benchmark (background).
python3 "$SAMPLER" --endpoint "$TARGET" --user "$USER" --password "$PASSWORD" \
    --interval 60 --duration 600 --out "$OUT" --insecure &
SAMPLER_PID=$!

echo "[INFO] Running OpenSearch Benchmark against $HOST ..."
opensearch-benchmark execute-test \
    --pipeline=benchmark-only \
    --workload-path="$WORKLOAD_DIR/workload.json" \
    --workload-params="$WORKLOAD_DIR/workload-params.json" \
    --target-hosts="$HOST" \
    --client-options="use_ssl:true,verify_certs:false,basic_auth_user:'$USER',basic_auth_password:'$PASSWORD'" \
    --results-file="$OUT/osb-report.txt" \
    --kill-running-processes || true

wait "$SAMPLER_PID" 2>/dev/null || true
echo "[INFO] OSB report: $OUT/osb-report.txt | metrics: $OUT/metrics.csv"
echo "[INFO] To compare two runs: opensearch-benchmark compare --baseline=<id> --contender=<id>"
