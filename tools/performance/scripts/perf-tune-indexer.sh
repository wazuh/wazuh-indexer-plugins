#!/bin/bash
#
# perf-tune-indexer.sh — apply performance-test tuning to a wazuh-indexer node.
#
# Applied identically by setup-aio.sh (real-world) and setup-indexer.sh (isolated) so
# both scenarios measure the SAME indexer configuration. Reads a flat YAML config
# (config/perf-tune.yml by default) and:
#   1. Pins the JVM heap to <heap_size> (-Xms/-Xmx). ALWAYS applied — this is a normal,
#      permanent setting, not reverted afterwards.
#   2. Writes the 5.x plugin settings (enriched_findings_index_enabled, catalog_update_on_*,
#      catalog_create_detectors, telemetry_enabled) verbatim from the YAML into opensearch.yml.
#      enriched_findings_index_enabled must be true for findings; catalog_update_on_start +
#      catalog_create_detectors drive the content-manager to sync the CTI catalog and build the
#      real detectors that match the perf event (needs CTI network from the indexer).
#   3. memory_lock=true (on-demand) → bootstrap.memory_lock + systemd LimitMEMLOCK=infinity.
#   4. disable_swap=true (on-demand) → swapoff -a for this boot (fstab untouched).
# Step 2 is skipped on 4.x where those plugins don't exist.
# It restarts the indexer once so everything takes effect together.
#
# Usage: perf-tune-indexer.sh <VERSION> [CONFIG_FILE]
#   VERSION     = MAJOR.MINOR (e.g. 5.0 / 4.14)
#   CONFIG_FILE = path to perf-tune.yml (default: ../config/perf-tune.yml next to this script)
#
# To revert the on-demand toggles: set them false in the YAML (or `swapon -a` / reboot for
# swap, remove the systemd override for memlock) and restart the indexer.
set -e

HERE="$(cd "$(dirname "$0")" && pwd)"
VERSION="${1:-5.0}"
CONFIG_FILE="${2:-$HERE/../config/perf-tune.yml}"
INDEXER_YML="/etc/wazuh-indexer/opensearch.yml"
JVM_OPTS="/etc/wazuh-indexer/jvm.options"
SYSTEMD_OVERRIDE_DIR="/etc/systemd/system/wazuh-indexer.service.d"

[[ -f "$CONFIG_FILE" ]] || { echo "[ERROR] perf-tune config not found: $CONFIG_FILE" >&2; exit 1; }

# Read a flat "key: value" from the YAML (ignores comments / inline trailing comments).
# The YAML is the single source of truth — a missing or empty key is a config error, not a
# silent default. Edit config/perf-tune.yml to change behavior.
yaml_get() {
    local key="$1" val
    if ! grep -qE "^[[:space:]]*${key}:" "$CONFIG_FILE"; then
        echo "[ERROR] required key '$key' missing in $CONFIG_FILE" >&2; exit 1
    fi
    val=$(grep -E "^[[:space:]]*${key}:" "$CONFIG_FILE" | head -n1 \
        | sed -E "s/^[[:space:]]*${key}:[[:space:]]*//; s/[[:space:]]*#.*$//; s/[[:space:]]*$//; s/^['\"]//; s/['\"]$//")
    if [[ -z "$val" ]]; then
        echo "[ERROR] key '$key' in $CONFIG_FILE has no value" >&2; exit 1
    fi
    printf '%s' "$val"
}

HEAP_SIZE=$(yaml_get heap_size)
MEMORY_LOCK=$(yaml_get memory_lock)
DISABLE_SWAP=$(yaml_get disable_swap)

echo "[INFO] perf-tune: heap=$HEAP_SIZE memory_lock=$MEMORY_LOCK disable_swap=$DISABLE_SWAP (version $VERSION)"

# Ensure $1 ends in a newline before we append with `>>`. The stock opensearch.yml /
# jvm.options may have NO trailing newline on their last line, so a bare `>>` would glue
# our setting onto it (e.g. `...version: truebootstrap.memory_lock: true`) → parse failure.
# `return 0` so the helper never trips `set -e` when no newline is needed (false test).
ensure_trailing_newline() { [[ -s "$1" && -n "$(tail -c1 "$1")" ]] && printf '\n' >> "$1"; return 0; }

# Set a "key: value" line in opensearch.yml, replacing any existing line for that key (so a
# re-run with a changed YAML value doesn't leave a duplicate key, which would fail to parse).
add_indexer_setting() {
    local line="$1" key esc
    key="${1%%:*}"
    esc=$(printf '%s' "$key" | sed 's/[.[\*^$/]/\\&/g')   # escape regex metachars (dots etc.)
    sed -i -E "/^[[:space:]]*${esc}:/d" "$INDEXER_YML"
    ensure_trailing_newline "$INDEXER_YML"
    printf '%s\n' "$line" >> "$INDEXER_YML"
}

# 1. 5.x plugin settings, taken verbatim from the YAML. These keys belong to the
#    security-analytics and content-manager plugins, which ship only with 5.x — adding them
#    to a 4.x opensearch.yml would stop the indexer from starting, so skip them there.
#    enriched_findings_index_enabled drives the findings pipeline; catalog_update_on_start +
#    catalog_create_detectors let the content-manager sync the CTI catalog and build the real
#    detectors that turn the perf event into findings (needs CTI network from the indexer).
if [[ "$VERSION" == 4.* ]]; then
    echo "[INFO] Version $VERSION is 4.x — no 5.x plugins; skipping plugin settings."
else
    add_indexer_setting "plugins.security_analytics.enriched_findings_index_enabled: $(yaml_get enriched_findings_index_enabled)"
    add_indexer_setting "plugins.content_manager.catalog.update_on_start: $(yaml_get catalog_update_on_start)"
    add_indexer_setting "plugins.content_manager.catalog.update_on_schedule: $(yaml_get catalog_update_on_schedule)"
    add_indexer_setting "plugins.content_manager.catalog.create_detectors: $(yaml_get catalog_create_detectors)"
    add_indexer_setting "plugins.content_manager.telemetry.enabled: $(yaml_get telemetry_enabled)"
fi

# 2. Pin JVM heap — drop any existing -Xms/-Xmx lines, then set ours. Permanent.
echo "[INFO] Setting JVM heap to $HEAP_SIZE in $JVM_OPTS"
sed -i -E '/^-Xm[sx]/d' "$JVM_OPTS"
ensure_trailing_newline "$JVM_OPTS"
printf '%s\n%s\n' "-Xms${HEAP_SIZE}" "-Xmx${HEAP_SIZE}" >> "$JVM_OPTS"

# 3. Memory locking (on-demand): opensearch.yml flag + systemd LimitMEMLOCK=infinity.
if [[ "$MEMORY_LOCK" == "true" ]]; then
    MEMLOCK_SETTING="bootstrap.memory_lock: true"
    if ! grep -qF "$MEMLOCK_SETTING" "$INDEXER_YML"; then
        echo "[INFO] Enabling $MEMLOCK_SETTING in $INDEXER_YML"
        ensure_trailing_newline "$INDEXER_YML"
        printf '%s\n' "$MEMLOCK_SETTING" >> "$INDEXER_YML"
    fi
    echo "[INFO] Setting LimitMEMLOCK=infinity for the wazuh-indexer service"
    mkdir -p "$SYSTEMD_OVERRIDE_DIR"
    printf '[Service]\nLimitMEMLOCK=infinity\n' > "$SYSTEMD_OVERRIDE_DIR/override.conf"
    systemctl daemon-reload
else
    echo "[INFO] memory_lock=false — leaving memory locking off."
fi

# 4. Swap (on-demand): disable for this boot only (fstab untouched → reverts on reboot).
if [[ "$DISABLE_SWAP" == "true" ]]; then
    echo "[INFO] Disabling swap (swapoff -a)"
    swapoff -a || true
else
    echo "[INFO] disable_swap=false — leaving swap enabled."
fi

echo "[INFO] Restarting wazuh-indexer to apply the perf-test config ..."
systemctl restart wazuh-indexer
for _ in $(seq 1 60); do
    code=$(curl -ks -o /dev/null -w '%{http_code}' https://localhost:9200 2>/dev/null || echo 000)
    [[ "$code" != "000" ]] && break
    sleep 5
done
echo "[INFO] Perf-test config applied (heap $HEAP_SIZE, detection=$DETECTION_ENABLED, memory_lock=$MEMORY_LOCK, disable_swap=$DISABLE_SWAP)."
