# Credential and TLS resolution

The Wazuh indexer package resolves its own credentials and TLS material rather than shipping
defaults. This page covers what that needs from the host and when it runs. For the accounts and
roles themselves, see [Security](plugins/security.md).

## Resolution happens once

`resolve-credentials.sh` runs from three places — `postinst` / `%post`, the unit's `ExecStartPre`,
and a container entrypoint — but it does its work **once**. A run that resolves everything it was
responsible for records the fact in `/var/lib/wazuh-indexer/.initialized`, and every later run
exits immediately without reading a key, a certificate or the credentials file.

That is not an optimisation. A password an operator rotated, or a certificate pair they replaced
with their own, has to survive a service restart and a package upgrade, and the only way to
guarantee that is to stop looking. A partial run — one that could not issue a certificate, say —
deliberately does **not** record completion, so the next install can still finish the job.

`resolve-credentials.sh --clear` is the one way back. It exists for container images built by
installing the package, which would otherwise bake one host's credentials into a layer every
container shares.

`indexer-security-init.sh` keeps its own state in `/var/lib/wazuh-indexer/.security-initialized`.
The two record different facts and are reached at different moments: resolution completes in
`postinst`, while the security configuration can only be uploaded once the node is running.

## Host dependencies

Both packages declare these (`Depends:` in `debian/control`, `Requires:` in the spec, where
`AutoReqProv` is off so nothing is inferred). They are listed here because the failure modes are
not obvious from the command names.

| Command | Provided by (yum / apt) | Used for |
| --- | --- | --- |
| `openssl` | `openssl` | Minting the bootstrap CA and issuing this node's certificate pair |
| `cmp` | `diffutils` | Checking that the CA private key matches its trust anchor |
| `flock` | `util-linux` | Serializing writes to `/etc/wazuh/credentials.env`, which every component shares |
| `runuser` | `util-linux` | Running `securityadmin.sh` as the service user |
| `ip` | `iproute` / `iproute2` | Deriving the certificate's Subject Alternative Names from the default-route interfaces |
| `hostname` | `hostname` | The certificate's common name and its first SAN |
| `pgrep` | `procps-ng` / `procps` | Detecting a running node, in `indexer-security-init.sh` |
| `stat`, `install` | `coreutils` | Validating ownership and mode on the credentials file and the CA directory |

`coreutils`, `util-linux` and `hostname` are Essential or `required` priority on Debian, so the
DEB package does not list them.

A full server installation of any supported distribution carries all of these already. A minimal
or container base image frequently does not — a pristine `opensearchproject/opensearch:3.6.0` has
none of `openssl`, `cmp`, `flock`, `runuser`, `ip`, `hostname` or `pgrep`. The failures are quiet
and easy to misread:

- a missing `openssl` leaves the node with no certificates;
- a missing `flock` stops any credential from being published at all;
- a missing `cmp` reports `root-ca.key does not match root-ca.pem` against a CA that is perfectly
  valid, because the shared helper cannot run the comparison.
