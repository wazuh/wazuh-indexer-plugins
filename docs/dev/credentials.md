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

`indexer-security-init.sh` keeps no state of its own. It is run by an operator, once, and the
package never calls it — so there is nothing for it to guard against repeating.

## How a password reaches the cluster

`internal_users.wazuh.yml` ships each account's `hash` as a `${NAME}` placeholder rather than a digest, so the package carries no usable credential. `resolve-credentials.sh` resolves the value, bcrypts it with the security plugin's `hash.sh`, and substitutes the digest in place.

The placeholder is deliberately bare. The security plugin substitutes `${env.X}`, `${envbc.X}` and `${envbase64.X}` itself, node-side, at every configuration load — which would tie each account to a variable that has to stay in the service environment for the life of the deployment. A placeholder with no such prefix is left untouched by the plugin.

Loading the result into the cluster stays a manual step, `indexer-security-init.sh`. A package cannot know whether other nodes of the same cluster are still to be installed elsewhere, so running it automatically would either race those nodes or overwrite what they uploaded.

## Resolver modes

`resolve-credentials.sh` takes one of four modes, and is invoked from `postinst` / `%post`, the unit's `ExecStartPre`, and a container entrypoint:

- `--install` — from a fresh install. Creates what it can, never fails, and is the only moment that issues certificates.
- `--upgrade` — fills in only what this host never had, and never touches the certificates.
- `--prestart` — from the unit. Refuses to start the service when something is unresolved.
- `--clear` — removes everything this component owns, so the next run resolves from nothing. For images built by installing the package, which would otherwise bake one host's credentials into a layer every container shares.

## Certificate resolution

Which case applies is decided entirely by what is present, with no mode flag — the presence of a private key beside the trust anchor is the signal, so a host never given one cannot sign:

| In the CA directory | Pair already in place | Result |
| --- | --- | --- |
| Nothing | No | Mint a CA, then self-issue |
| Anchor and key | No | Issue from the CA found |
| Anchor only | Yes | Use both, generate nothing |
| Anchor only | No | Unresolved; the service will not start |

The Subject Alternative Names default to the hostname, the FQDN, loopback and the global addresses of default-route interfaces. `WAZUH_INDEXER_CERT_SANS` replaces that list wholesale.

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
