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
DURATION=600      # sampler window (s) alongside the benchmark
INTERVAL=60       # sampler cadence (s)
OUT="./runs/osb-$(date +%Y%m%d-%H%M%S)"
NO_HOST=""        # set --no-host so the sampler skips local psutil (it runs off-host here)
NODE_EXPORTER=""  # node_exporter endpoint (host:9100) for the indexer's host metrics

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target)         TARGET="$2"; shift 2 ;;
        --user)           USER="$2"; shift 2 ;;
        --password)       PASSWORD="$2"; shift 2 ;;
        --docs)           DOCS="$2"; shift 2 ;;
        --duration)       DURATION="$2"; shift 2 ;;
        --interval)       INTERVAL="$2"; shift 2 ;;
        --out)            OUT="$2"; shift 2 ;;
        --no-host)        NO_HOST="--no-host"; shift ;;
        --node-exporter)  NODE_EXPORTER="$2"; shift 2 ;;
        *) echo "Usage: $0 [--target URL] [--user U] [--password P] [--docs N] [--duration S] [--interval S] [--out DIR] [--no-host] [--node-exporter HOST:9100]"; exit 1 ;;
    esac
done

NE_ARG=()
[[ -n "$NODE_EXPORTER" ]] && NE_ARG=(--node-exporter "$NODE_EXPORTER")

mkdir -p "$OUT"

if [[ ! -f "$WORKLOAD_DIR/documents.json" ]]; then
    echo "[INFO] Corpus missing — generating $DOCS documents..."
    python3 "$SCRIPT_DIR/gen-corpora.py" --docs "$DOCS"
fi

# Strip scheme for OSB --target-hosts and pass TLS/auth via client options.
HOST="${TARGET#https://}"; HOST="${HOST#http://}"

# Sample cluster internals alongside the benchmark (background) for the window.
python3 "$SAMPLER" --endpoint "$TARGET" --user "$USER" --password "$PASSWORD" \
    --interval "$INTERVAL" --duration "$DURATION" --out "$OUT" --insecure $NO_HOST ${NE_ARG[@]+"${NE_ARG[@]}"} &
SAMPLER_PID=$!

# OSB renamed the test-execution subcommand from `execute-test` to `run` in newer
# releases. Pick whichever this install provides.
if opensearch-benchmark --help 2>&1 | grep -qF 'execute-test'; then
    OSB_SUBCMD="execute-test"
else
    OSB_SUBCMD="run"
fi

echo "[INFO] Running OpenSearch Benchmark ($OSB_SUBCMD) against $HOST ..."
opensearch-benchmark "$OSB_SUBCMD" \
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
