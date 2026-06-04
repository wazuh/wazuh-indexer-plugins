#!/bin/bash
#
# lib.sh — shared helpers for the Vagrant measurement runners
# (run-real-world.sh / run-isolated.sh). Sourced, not executed.
#
# Callers set their own `set -euo pipefail` and `cd` into vagrant/. The fallback
# command substitutions below end in `|| true` on purpose: a missing guest file or
# a non-zero `vagrant ssh`/`vagrant status` is an expected "try the next source"
# path, not a fatal error, and must not trip `pipefail`.

# perf_rsync [machine] — push the latest scripts into the VM(s). Non-fatal: on
# VirtualBox the default synced folder is vboxsf (no rsync folders), so
# `vagrant rsync` is a no-op/error there; libvirt syncs host→guest and needs it.
perf_rsync() {
    echo "[INFO] Syncing latest scripts to the VMs ..."
    if ! vagrant rsync "$@" >/dev/null 2>&1; then
        echo "[WARN] 'vagrant rsync ${*:-}' did nothing or failed — expected on VirtualBox" >&2
        echo "       (vboxsf); on libvirt the VMs may run stale scripts." >&2
    fi
}

# perf_resolve_password <machine> — resolve the admin password into the global
# PASSWORD. Order: existing $PASSWORD (e.g. --password), else the file captured
# during provisioning read from the guest, else ../runs/admin-password.txt. The
# guest file lives at /var/lib/wazuh-perf (NOT under the synced /opt/perf, which
# the rsync above would prune). Exits 1 with guidance if none is found.
perf_resolve_password() {
    local machine="$1"
    if [[ -z "${PASSWORD:-}" ]]; then
        PASSWORD="$(vagrant ssh "$machine" -c 'sudo cat /var/lib/wazuh-perf/admin-password.txt 2>/dev/null' 2>/dev/null | tr -d '\r\n' || true)"
    fi
    if [[ -z "$PASSWORD" && -f ../runs/admin-password.txt ]]; then
        PASSWORD="$(cat ../runs/admin-password.txt)"
    fi
    if [[ -z "$PASSWORD" ]]; then
        echo "[ERROR] No indexer password found on the '$machine' VM (/var/lib/wazuh-perf/admin-password.txt)." >&2
        echo "        Pass --password '<admin pass>', or check the setup script output for a capture warning." >&2
        exit 1
    fi
}

# perf_detect_version <machine> — resolve the INSTALLED wazuh-indexer version
# (ground truth) into the globals VERSION and LABEL. --version 4.14 installs the
# latest 4.14.x, and the label/output dir reflect that exact patch (e.g. 4.14.1).
# Any pre-set $VERSION is only a fallback if the package query fails.
perf_detect_version() {
    local machine="$1" raw detected
    raw="$(vagrant ssh "$machine" -c "dpkg-query -W -f='\${Version}' wazuh-indexer 2>/dev/null || rpm -q --qf '%{VERSION}-%{RELEASE}' wazuh-indexer 2>/dev/null" 2>/dev/null | tr -d '\r\n' || true)"
    detected="${raw##*:}"        # strip any epoch
    detected="${detected%%-*}"   # strip Debian/RPM revision → upstream version
    VERSION="${detected:-${VERSION:-}}"
    if [[ -z "$VERSION" ]]; then
        echo "[ERROR] Could not determine the wazuh-indexer version from the '$machine' VM. Pass --version X.Y.Z." >&2
        exit 1
    fi
    LABEL="wazuh-$VERSION"
    echo "[INFO] Run label: $LABEL (installed version)"
}

# perf_pull_results <machine> <guest_dir> <local_dir> — copy a guest directory back
# over SSH. base64 -w0 (no wrapping) + host-side stripping of non-base64 chars
# defends against CR/PTY mangling by `vagrant ssh`.
perf_pull_results() {
    local machine="$1" guest_dir="$2" local_dir="$3"
    mkdir -p "$local_dir"
    vagrant ssh "$machine" -c "sudo tar -czf - -C $guest_dir . | base64 -w0" 2>/dev/null \
        | tr -dc 'A-Za-z0-9+/=' | base64 -d | tar -xzf - -C "$local_dir"
}
