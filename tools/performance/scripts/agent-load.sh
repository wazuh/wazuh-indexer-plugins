#!/bin/bash
#
# agent-load.sh — generate FIM + Logcollector events in a loop on a Wazuh agent.
#
# Run this ON EACH agent host (beta2) for the duration of the measurement window.
# It drives the two event sources used by the primary scenario:
#   - FIM:         creates/modifies/deletes files in a monitored directory
#   - Logcollector: appends lines to a monitored log file
#
# The agent must be configured to watch these paths. Add to /var/ossec/etc/ossec.conf
# (then `systemctl restart wazuh-agent`):
#
#   <syscheck>
#     <directories check_all="yes" realtime="yes">/var/perf-fim</directories>
#   </syscheck>
#   <localfile>
#     <log_format>syslog</log_format>
#     <location>/var/perf-logs/load.log</location>
#   </localfile>
#
set -euo pipefail

FIM_DIR="/var/perf-fim"
LOG_FILE="/var/perf-logs/load.log"
RATE=10          # events per second (per source)
DURATION=3600    # seconds

while [[ $# -gt 0 ]]; do
    case "$1" in
        --fim-dir)   FIM_DIR="$2"; shift 2 ;;
        --log-file)  LOG_FILE="$2"; shift 2 ;;
        --rate)      RATE="$2"; shift 2 ;;
        --duration)  DURATION="$2"; shift 2 ;;
        *) echo "Usage: $0 [--fim-dir D] [--log-file F] [--rate N] [--duration S]"; exit 1 ;;
    esac
done

mkdir -p "$FIM_DIR" "$(dirname "$LOG_FILE")"
sleep_between=$(awk "BEGIN { printf \"%.4f\", 1.0 / $RATE }")
end=$(( $(date +%s) + DURATION ))

echo "[INFO] FIM dir: $FIM_DIR | log: $LOG_FILE | rate: ${RATE}/s | duration: ${DURATION}s"

i=0
while [[ $(date +%s) -lt $end ]]; do
    # FIM event: churn a file (create → modify → delete on rotation).
    f="$FIM_DIR/file_$(( i % 100 )).txt"
    echo "perf-fim content $i $(date +%s%N)" > "$f"
    [[ $(( i % 100 )) -eq 99 ]] && rm -f "$FIM_DIR"/file_*.txt

    # Logcollector event: append a syslog-shaped line.
    printf '%s perf-host wazuh-perf[%d]: synthetic event seq=%d\n' \
        "$(date '+%b %d %H:%M:%S')" "$$" "$i" >> "$LOG_FILE"

    i=$(( i + 1 ))
    sleep "$sleep_between"
done

echo "[INFO] Generated $i FIM + $i log events over ${DURATION}s"
