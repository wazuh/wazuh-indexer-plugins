#!/bin/bash
#
# analyze.sh — generate the cross-version comparison + timeline plots from the
# runs in runs/, automatically.
#
# Discovers every runs/<scenario>-<version>/metrics.csv, groups them by scenario
# (real-world / isolated), and for each scenario that has runs writes:
#   <scenario>-compare.md    (analyze/compare.py — needs >=2 versions)
#   <scenario>-timeline.png  (analyze/plot.py)
#
# Comparisons only make sense within a scenario (same workload), so runs are never
# mixed across scenarios. Each run's label comes from its run-metadata.json, else
# the directory name.
#
#   ./analyze.sh                       # analyze every scenario found in runs/
#   ./analyze.sh --scenario real-world # restrict to one scenario
#   ./analyze.sh --runs-dir /path/runs # analyze runs from another location
#
set -euo pipefail

cd "$(dirname "$0")"

RUNS_DIR="runs"
ONLY_SCENARIO=""

usage() { echo "Usage: $0 [--scenario real-world|isolated] [--runs-dir DIR]"; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        --runs-dir) RUNS_DIR="$2"; shift 2 ;;
        --scenario) ONLY_SCENARIO="$2"; shift 2 ;;
        -h|--help)  usage; exit 0 ;;
        *) echo "[ERROR] Unknown argument: $1" >&2; usage >&2; exit 1 ;;
    esac
done

[[ -d "$RUNS_DIR" ]] || { echo "[ERROR] No runs directory: $RUNS_DIR" >&2; exit 1; }

# Emit `label=path` for a run dir; label from run-metadata.json, else the dir name.
pair_for() {
    local d="${1%/}" name label l
    name="$(basename "$d")"
    label="$name"
    if [[ -f "$d/run-metadata.json" ]]; then
        l="$(grep -o '"label"[[:space:]]*:[[:space:]]*"[^"]*"' "$d/run-metadata.json" \
             | sed 's/.*"\([^"]*\)"$/\1/' || true)"
        [[ -n "$l" ]] && label="$l"
    fi
    printf '%s=%s' "$label" "$d/metrics.csv"
}

SCENARIOS=(real-world isolated)
[[ -n "$ONLY_SCENARIO" ]] && SCENARIOS=("$ONLY_SCENARIO")

ANY=0
for s in "${SCENARIOS[@]}"; do
    pairs=()
    for d in "$RUNS_DIR/$s"-*/; do
        d="${d%/}"
        [[ -f "$d/metrics.csv" ]] || continue   # skips the unmatched glob literal too
        pairs+=("$(pair_for "$d")")
    done
    [[ ${#pairs[@]} -eq 0 ]] && continue
    ANY=1

    echo "[INFO] $s: ${#pairs[@]} run(s) — ${pairs[*]}"
    python3 analyze/plot.py "${pairs[@]}" --out "$s-timeline.png"
    if [[ ${#pairs[@]} -ge 2 ]]; then
        python3 analyze/compare.py "${pairs[@]}" --out "$s-compare.md"
    else
        echo "[INFO] $s: only one run — skipping compare (needs >=2 versions). Timeline written."
    fi
done

[[ "$ANY" -eq 1 ]] || {
    echo "[ERROR] No runs with metrics.csv under $RUNS_DIR/ (looked for real-world-*/ and isolated-*/)." >&2
    exit 1
}

echo "[INFO] Done. See <scenario>-compare.md and <scenario>-timeline.png in $(pwd)."
