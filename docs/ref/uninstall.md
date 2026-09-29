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

A purge never deletes indexed data. These files stay on disk:

- the node and admin certificates, including their private keys, in `/etc/wazuh-indexer/certs/`
- the keystore, `/etc/wazuh-indexer/opensearch.keystore`
- the indexed data, in `/var/lib/wazuh-indexer/`
- the logs, in `/var/log/wazuh-indexer/`
- any directory set in `path.home`, `path.data`, `path.logs`, `path.repo` or `path.shared_data`

Before it removes the `wazuh-indexer` user and group, the purge makes `root` the owner of these files and removes group and other access from them. The user's ID is then free for the system to give to another account, but that account cannot read anything the Wazuh indexer left behind.

The purge lists every directory it kept:

```
Kept /var/lib/wazuh-indexer, now owned by root. Reinstalling wazuh-indexer takes it back.
```

For a directory set in one of those settings outside the default locations, it prints the command to run before a new installation uses it:

```
/srv/snapshots now belongs to root. Before a new wazuh-indexer installation uses it, run: chown -R wazuh-indexer:wazuh-indexer /srv/snapshots
```

### Shared credentials

The purge removes the Wazuh indexer's passwords from `/etc/wazuh/credentials.env` (see [Retrieving the generated credentials](getting-started/installation.md#retrieving-the-generated-credentials)) and leaves the other components' passwords in place. When no component's passwords are left, it also removes the root CA from `/etc/wazuh/ca/`.

### When the user and group are kept

The purge keeps the `wazuh-indexer` user and group, so that no other account can take their IDs, in two cases:

- A file cannot be given to `root`, for example because it is on a read-only file system:

  ```
  Some files owned by wazuh-indexer under /srv/snapshots could not be handed over to root; keeping the wazuh-indexer user and group so their IDs are not reused.
  ```

- The purge cannot tell for certain which directories `opensearch.yml` configured: the file could not be read, or one of the settings above holds a relative path or a `${...}` placeholder:

  ```
  Could not read where opensearch.yml kept data, logs and snapshots; keeping the wazuh-indexer user and group so their IDs are not reused.
  ```

  The default directories are still given to `root`. The directories you configured are not, so find them in your own records of the configuration.

To finish the removal, make the files writable if needed, give them to `root`, then delete the user and the group:

```bash
chown -R root:root /srv/snapshots
chmod -R go-rwx /srv/snapshots
userdel wazuh-indexer
groupdel wazuh-indexer
```

## Reinstalling after a purge

Installing the package again gives the kept files in the default locations back to the `wazuh-indexer` user, and the node uses the certificates it finds in `/etc/wazuh-indexer/certs/` instead of issuing new ones.

Directories outside the default locations are not given back. Set them in `opensearch.yml` again, then run the `chown` command the purge printed for each one.

## Deleting everything

To remove the Wazuh indexer and all its data for good, purge the package, then delete the directories it kept, including any you set in `opensearch.yml`:

```bash
apt-get purge wazuh-indexer -y   # or: yum remove wazuh-indexer -y
rm -rf /etc/wazuh-indexer/ /var/lib/wazuh-indexer/ /var/log/wazuh-indexer/
```

This cannot be undone: it deletes the indexed data and the certificates' private keys.
