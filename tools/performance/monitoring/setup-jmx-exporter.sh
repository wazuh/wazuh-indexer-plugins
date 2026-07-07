#!/bin/bash
#
# setup-jmx-exporter.sh — attach the Prometheus JMX exporter to the wazuh-indexer JVM
# as a javaagent, exposing deep JVM metrics (heap pools, GC, threads, buffer pools) on
# http://<indexer>:9404/metrics for Prometheus to scrape.
#
# Runs on the INDEXER host. Uses the in-process javaagent (NOT a remote JMX port), so
# nothing extra is opened beyond :9404. It appends a -javaagent line to jvm.options and
# restarts the indexer so the agent loads.
#
#   sudo ./setup-jmx-exporter.sh [--version 0.20.0] [--port 9404]
#
set -e

JMX_VERSION="0.20.0"
PORT="9404"
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version) JMX_VERSION="$2"; shift 2 ;;
        --port)    PORT="$2"; shift 2 ;;
        *) echo "Usage: $0 [--version X.Y.Z] [--port N]"; exit 1 ;;
    esac
done

HERE="$(cd "$(dirname "$0")" && pwd)"
DEST=/opt/jmx_exporter
JAR="$DEST/jmx_prometheus_javaagent.jar"
CFG="$DEST/config.yaml"
JVM_OPTS="/etc/wazuh-indexer/jvm.options"
URL="https://repo1.maven.org/maven2/io/prometheus/jmx/jmx_prometheus_javaagent/${JMX_VERSION}/jmx_prometheus_javaagent-${JMX_VERSION}.jar"

mkdir -p "$DEST"
echo "[INFO] Downloading jmx_prometheus_javaagent ${JMX_VERSION}"
curl -sS --fail -L "$URL" -o "$JAR"
install -m 0644 "$HERE/jmx-exporter-config.yaml" "$CFG"
# wazuh-indexer runs as the wazuh-indexer user — the jar/config must be world-readable.
chmod -R a+rX "$DEST"

# Append the javaagent line to jvm.options (idempotent — drop any prior one first).
sed -i '\#-javaagent:.*jmx_prometheus_javaagent#d' "$JVM_OPTS"
[[ -s "$JVM_OPTS" && -n "$(tail -c1 "$JVM_OPTS")" ]] && printf '\n' >> "$JVM_OPTS"
printf '%s\n' "-javaagent:${JAR}=${PORT}:${CFG}" >> "$JVM_OPTS"
echo "[INFO] Added JMX javaagent to $JVM_OPTS (port $PORT)"

echo "[INFO] Restarting wazuh-indexer to load the JMX exporter ..."
systemctl restart wazuh-indexer
for _ in $(seq 1 60); do
    code=$(curl -ks -o /dev/null -w '%{http_code}' https://localhost:9200 2>/dev/null || echo 000)
    [[ "$code" != "000" ]] && break
    sleep 5
done
echo "[INFO] JMX exporter active on :$PORT — verify: curl -s http://localhost:${PORT}/metrics | head"
