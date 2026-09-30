# Uninstall

> **Note**: You need root user privileges to run all the commands described below.

Removing the package stops the Wazuh indexer and deletes its program files. What happens to the configuration, the credentials and the data depends on how you remove it.

## Remove or purge

On DEB systems there are two ways to remove the package:

- **Remove** keeps the configuration, the credentials, the certificates, the logs, the indexed data and the `wazuh-indexer` user. Use it when you intend to install the Wazuh indexer again on this host.

  ```bash
  apt-get remove wazuh-indexer -y
  ```

- **Purge** also removes the configuration files, the Wazuh indexer's credentials, and the `wazuh-indexer` user and group. See [What a purge keeps](#what-a-purge-keeps) for what stays on disk.

  ```bash
  apt-get purge wazuh-indexer -y
  ```

On RPM systems, removing the package always does what a purge does:

```bash
yum remove wazuh-indexer -y
```

## What a purge keeps

A purge never deletes indexed data. It manages the package's own directories, and only these:

- `/etc/wazuh-indexer/` — the configuration, including the node and admin certificates with their private keys, and the keystore
- `/usr/share/wazuh-indexer/` — the installation
- `/var/lib/wazuh-indexer/` — the indexed data
- `/var/log/wazuh-indexer/` — the logs

Before it removes the `wazuh-indexer` user and group, the purge makes `root` the owner of what the Wazuh indexer left in these directories and removes group and other access from it. The user's ID is then free for the system to give to another account, but that account cannot read anything left there.

The purge lists every directory it kept:

```
Kept /var/lib/wazuh-indexer, now owned by root. Reinstalling wazuh-indexer takes it back.
```

If a file cannot be given to `root`, for example because the directory is on a read-only file system, the purge names the directory instead of listing it as kept, and still removes the user and group:

```
Some files under /var/log/wazuh-indexer could not be handed over to root; they keep the ID of the removed wazuh-indexer user.
```

Give those files to `root` yourself once the file system is writable:

```bash
chown -R root:root /var/log/wazuh-indexer
chmod -R go-rwx /var/log/wazuh-indexer
```

### Directories outside the default locations

The purge does not touch any directory set in `opensearch.yml` outside the four above, such as a custom `path.data`, `path.logs` or `path.repo`. Such a directory can be shared with the other nodes of the cluster, as a shared file system snapshot repository must be, so changing it on the node being purged could break them. Its files keep the ID of the removed `wazuh-indexer` user, and an account created later can be given that ID. The purge reminds you every time it runs:

```
Note: the package only manages /etc/wazuh-indexer, /usr/share/wazuh-indexer, /var/lib/wazuh-indexer and /var/log/wazuh-indexer.
Directories set elsewhere in opensearch.yml (a custom path.data, path.logs or path.repo) are left as they are, still owned by the ID of the removed wazuh-indexer user.
```

Handling these directories is up to you, before or after the purge. Delete the ones you no longer need. Give the ones only this node used, and that you want to keep, to `root`:

```bash
chown -R root:root /srv/indexer-data
chmod -R go-rwx /srv/indexer-data
```

Leave a snapshot repository that other nodes still use as it is.

### Shared credentials

The purge removes the Wazuh indexer's passwords from `/etc/wazuh/credentials.env` (see [Retrieving the generated credentials](getting-started/installation.md#retrieving-the-generated-credentials)) and leaves the other components' passwords in place. When no component's passwords are left, it also removes the root CA from `/etc/wazuh/ca/`.

## Reinstalling after a purge

Installing the package again gives the files kept in the four directories back to the `wazuh-indexer` user, and the node uses the certificates it finds in `/etc/wazuh-indexer/certs/` instead of issuing new ones.

A directory outside them is not given back. Set it in `opensearch.yml` again, then give it to the new user:

```bash
chown -R wazuh-indexer:wazuh-indexer /srv/indexer-data
```

## Deleting everything

To remove the Wazuh indexer and all its data for good, purge the package, then delete the directories it kept, and any directory you set in `opensearch.yml` that no other node uses:

```bash
apt-get purge wazuh-indexer -y   # or: yum remove wazuh-indexer -y
rm -rf /etc/wazuh-indexer/ /usr/share/wazuh-indexer/ /var/lib/wazuh-indexer/ /var/log/wazuh-indexer/
```

This cannot be undone: it deletes the indexed data and the certificates' private keys.
