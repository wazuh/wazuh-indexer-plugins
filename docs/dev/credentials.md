# Credential and TLS resolution

The Wazuh indexer package resolves its own credentials and TLS material rather than shipping
defaults. This page covers what that needs from the host and when it runs. For the accounts and
roles themselves, see [Security](plugins/security.md).

## Resolution happens once

`resolve-credentials.sh` runs from four places — `postinst` / `%post`, the unit's `ExecStartPre`,
the SysV `start` path, and a container entrypoint — but it does its work **once**. A run that
resolves everything it was responsible for records the fact in
`/var/lib/wazuh-indexer/.initialized`, and every later run exits immediately without reading a key,
a certificate or the credentials file.

The marker, not the mode, is what makes that true. Every mode resolves the same things — the
passwords, the certificates and the trust anchor in the bundled JDK — so a run that finds the
marker absent finishes whatever an earlier one could not.

That is not an optimisation. A password an operator rotated, or a certificate pair they replaced
with their own, has to survive a service restart and a package upgrade, and the only way to
guarantee that is to stop looking. A partial run — one that could not issue a certificate, say —
deliberately does **not** record completion, so the next install can still finish the job.

`resolve-credentials.sh --clear` is the one way back. It takes back every half of everything this
component resolved: the passwords published in `/etc/wazuh/credentials.env` and the digests in
`internal_users.yml`, which return to their `${NAME}` placeholders; the certificates, a bootstrap
CA it minted itself, and the node and admin DNs derived from them; and the CA entry in the bundled
JDK truststore. A trust anchor with no private key beside it was issued elsewhere, so it stays.

It exists for container images built by installing the package, which would otherwise bake one
host's credentials into a layer every container shares. The next start resolves all of it again.

`indexer-security-init.sh` keeps no state of its own. It is run by an operator, once, and the
package never calls it — so there is nothing for it to guard against repeating.

## How a password reaches the cluster

`internal_users.wazuh.yml` ships each account's `hash` as a `${NAME}` placeholder rather than a digest, so the package carries no usable credential. `resolve-credentials.sh` resolves the value, bcrypts it with the security plugin's `hash.sh`, and substitutes the digest in place.

The placeholder is deliberately bare. The security plugin substitutes `${env.X}`, `${envbc.X}` and `${envbase64.X}` itself, node-side, at every configuration load — which would tie each account to a variable that has to stay in the service environment for the life of the deployment. A placeholder with no such prefix is left untouched by the plugin.

The digest and the published password are one credential in two halves, and resolution keeps them together rather than writing either alone. An account whose placeholder is already gone while nothing supplies its password — a host upgrading from a version that predates this mechanism, whose `internal_users.yml` the package manager kept — is reported and left as it is, instead of being given a freshly generated password that its digest would not match.

Loading the result into the cluster stays a manual step, `indexer-security-init.sh`. A package cannot know whether other nodes of the same cluster are still to be installed elsewhere, so running it automatically would either race those nodes or overwrite what they uploaded.

## Resolver modes

`resolve-credentials.sh` takes one of four modes:

- `--install` — from a fresh install. Creates what it can and never fails: a maintainer script that aborts leaves the package half-configured. It is the only mode that replaces a DN setting that already has a value.
- `--upgrade` — fills in only what this host never had.
- `--prestart` — from the unit's `ExecStartPre` and from the SysV `start` path. Refuses to start the service when something is unresolved, naming it.
- `--clear` — takes back everything this component resolved, so a later run resolves from nothing. See [Resolution happens once](#resolution-happens-once).

## Certificate resolution

Which case applies is decided entirely by what is present, with no mode flag — the presence of a private key beside the trust anchor is the signal, so a host never given one cannot sign:

| In the CA directory | Pair already in place | Result |
| --- | --- | --- |
| Nothing | No | Mint a CA, then self-issue |
| Anchor and key | No | Issue from the CA found |
| Anchor only | Yes | Use both, generate nothing |
| Anchor only | No | Unresolved; the service will not start |

The Subject Alternative Names default to the hostname, the FQDN, loopback and the global addresses of default-route interfaces. `WAZUH_INDEXER_CERT_SANS` replaces that list wholesale.

The subject is `/C=US/L=California/O=Wazuh/OU=Wazuh/CN=<node>`, the same order `wazuh-certs-tool.sh` uses. The order matters: the Security plugin compares the rendered Distinguished Name, so a deployment that replaces the package certificates with the tool's own keeps the DNs already written into `opensearch.yml` valid.

### Distinguished names

A node whose DN is not listed is rejected by the cluster, so `plugins.security.nodes_dn` and `plugins.security.authcz.admin_dn` are filled from the certificates in the same step that resolves them. `--install` replaces whatever those keys hold. Every other mode fills them only when they are empty, because by then the list may be the operator's own — one entry per node of their cluster.

This is what makes the deferred case work. A deployment that brings its own PKI installs the package with only the trust anchor in the CA directory, so the install cannot issue anything and records no completion; the pair is staged afterwards, and the next start finishes the job, DNs included.

### The JDK truststore

The bundled JDK has to trust the Wazuh CA, so the resolver imports `certs/root-ca.pem` into `jdk/lib/security/cacerts` under the alias `wazuh-root-ca` whenever it resolves the certificates, and `--clear` deletes it again. It belongs to the resolver rather than to the maintainer scripts for both of those reasons: a pair staged after the install reaches the truststore too, and an image built by installing the package does not keep the build host's CA in every copy.

## File ownership

Root runs `bin/resolve-credentials.sh` — from the maintainer scripts and from the unit's
`ExecStartPre` — and that script sources `lib/wazuh-credentials.sh`. So the product tree is
**`root`-owned**, group `wazuh-indexer`, mode `750`/`640`: the service account reads and executes
everything and writes nothing. A service account able to rewrite either file could have root run
its own code.

Two directories under the product tree are exceptions, because the service writes them at runtime:

- `engine/` — sockets, logs and data
- `plugins/wazuh-indexer-content-manager/snapshots/` — the content manager deletes the shipped
  snapshot once it has consumed it

**Adding a file the service must write means adding a third exception**, in the DEB `postinst` and
in the spec's `%files`. Adding one it only reads needs nothing: the default covers it. The
acceptance suite asserts both the root ownership and the two exceptions, so getting this wrong
fails the build rather than shipping quietly.

The same reasoning applies outside the product tree. `/etc/default/wazuh-indexer` and
`/usr/lib/sysctl.d/wazuh-indexer.conf` are read by systemd as root, so both stay root-owned.

It applies to the maintainer scripts too. The purge path needs the shared helper after the package
manager has already deleted it, so the removal stashes a copy — in `/etc/wazuh`, which is root-owned
and root-only, never in a directory the service account can write. Root sources that copy, and
checks first that it is a regular file owned by root and writable by nobody else. The same rule
covers the SysV script, which reads a pid from a file the service account owns and therefore
confirms the process is the indexer's before signalling it.

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
| `stat`, `install` | `coreutils` | Validating ownership and mode on the credentials file, the CA directory and anything root sources |

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
