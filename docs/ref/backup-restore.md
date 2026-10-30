# Back up and restore

In this section you can find instructions on how to create and restore a backup of your Wazuh Indexer key files, preserving file permissions, ownership, and path. Later, you can move this folder contents back to the corresponding location to restore your certificates and configurations. Backing up these files is useful in cases such as moving your Wazuh installation to another system.

> **Note**: This backup only restores the configuration files, not the data. To back up the data stored in the indexer, use snapshots, as described in [Backing up the data](#backing-up-the-data).

## Backing up the data

Data is backed up with [snapshots](https://docs.opensearch.org/3.6/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/), which are written to a repository. A filesystem repository can only be registered under a directory named in `path.repo`, a setting the node reads at start and that cannot be changed through the API.

The installation writes one into `/etc/wazuh-indexer/opensearch.yml`, so a repository can be registered from the Wazuh dashboard or the API with no edit and no restart:

```yaml
path.repo: ["/var/lib/wazuh-indexer/backup"]
```

An upgrade adds it to a node installed before the setting existed, and only when the key is absent: a location you changed is never corrected, and one you removed on purpose comes back at the next upgrade, not at the next start.

The package creates `/var/lib/wazuh-indexer/backup` empty, `wazuh-indexer:wazuh-indexer` with mode `750`, and writes nothing to it. Once it holds snapshots, removing or purging the package keeps it, handed over to root; while it is still empty it goes with the rest of the package. In the Docker image the directory is `/usr/share/wazuh-indexer/backup` instead, and `path.repo` names that one.

Register the repository once, from any node of the cluster:

```bash
curl -k -u <INDEXER_USERNAME>:<INDEXER_PASSWORD> -XPUT "https://<INDEXER_IP_ADDRESS>:9200/_snapshot/<REPOSITORY_NAME>" \
  -H 'Content-Type: application/json' \
  -d '{"type": "fs", "settings": {"location": "/var/lib/wazuh-indexer/backup"}}'
```

### Where the snapshots are written

**The directory is on the data disk.** A snapshot there covers the most common restores: an index deleted by mistake, a failed upgrade, corrupted data. It does not survive the loss of the disk it sits on, which is what a backup is for.

**For anything beyond that, point `path.repo` somewhere else.** `/var/lib/wazuh-indexer/backup` is inside a directory the package manages: installing takes ownership of everything in it, and removing the package hands it over to root. That is right for a directory of this node's own making, and wrong for a volume you mounted or for a repository shared with other nodes. Give those a location outside `/etc/wazuh-indexer`, `/usr/share/wazuh-indexer`, `/var/lib/wazuh-indexer` and `/var/log/wazuh-indexer`, which the package never touches, and name it in `path.repo`:

```yaml
path.repo: ["/srv/wazuh-indexer-backup"]
```

**On a cluster it has to be a shared filesystem.** Every node writes the shards it holds into the repository, so an `fs` repository must be the same filesystem, mounted at the same path, on every node, over NFS for example. A directory that is local to one node is rejected as soon as another node has to write to it. Mount it outside the package's directories for the reason above, give it the same user and group IDs on every node, because each node writes as its own `wazuh-indexer` account, and list it in `path.repo` on every node.

**Snapshots on the data disk count toward the disk watermarks.** The indexer measures the filesystem, not the directory, so snapshots kept beside the data push it toward the low watermark, where it stops allocating new shards, the high watermark, where it moves shards off the node, and the flood-stage watermark, where it makes indices read-only. A volume of its own keeps the two apart.

### Nodes installed before this setting

The upgrade adds `path.repo` and creates the directory, but the setting is read at start, so the node picks it up at its next restart:

```bash
systemctl restart wazuh-indexer
```

## Creating a backup

To create a backup of the Wazuh indexer, follow these steps. Repeat them on every cluster node you want to back up.

> **Note**: You need root user privileges to run all the commands described below.

### Preparing the backup

1. Back up the existing Wazuh indexer security configuration files.

    ```bash
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh --options "-backup /etc/wazuh-indexer/opensearch-security -icl -nhnv"
    ```

2. Create the destination folder to store the files. For version control, add the date and time of the backup to the name of the folder.

    ```bash
    backup_folder=~/wazuh_files_backup/$(date +%F_%H:%M)
    mkdir -p $backup_folder && echo $backup_folder
    ```

3. Save the host information.

    ```bash
    cat /etc/*release* > $backup_folder/host-info.txt
    echo -e "\n$(hostname): $(hostname -I)" >> $backup_folder/host-info.txt
    ```

### Backing up the Wazuh indexer

Back up the Wazuh indexer certificates and configuration

```bash
rsync -aREz \
/etc/wazuh-indexer/certs/ \
/etc/wazuh-indexer/jvm.options \
/etc/wazuh-indexer/jvm.options.d \
/etc/wazuh-indexer/log4j2.properties \
/etc/wazuh-indexer/opensearch.yml \
/etc/wazuh-indexer/opensearch.keystore \
/etc/wazuh-indexer/opensearch-security/ \
/etc/wazuh-indexer/wazuh-indexer-reports-scheduler/ \
/etc/wazuh-indexer/wazuh-indexer-notifications/ \
/etc/wazuh-indexer/wazuh-indexer-notifications-core/ \
/etc/wazuh-indexer/ca/ \
/etc/wazuh-indexer/export/ \
/usr/lib/sysctl.d/wazuh-indexer.conf $backup_folder
```

`ca/` holds the certificate authority that signed the node's certificates, including its private key when the package created it, and `export/` the passwords and the CA certificate the node published for the Wazuh manager and the Wazuh dashboard. Back up `/etc/wazuh-indexer/local.env` too if you created it.

Compress the files and transfer them to the new server. The archive contains private keys, so store and transfer it securely:

```bash
tar -cvzf wazuh-indexer-backup.tar.gz $backup_folder
```

## Restoring Wazuh indexer from backup

This guide explains how to restore a backup of your configuration files.

>**Note**: This guide is designed specifically for restoration from a backup of the same version.

---

>**Note**: For a multi-node setup, there should be a backup file for each node within the cluster. You need root user privileges to execute the commands below.

### Preparing the data restoration

1. In the new node, move the compressed backup file to the root `/` directory:

    ```bash
    mv wazuh-indexer-backup.tar.gz /
    cd /
    ```

2. Decompress the backup files and change the current working directory to the directory based on the date and time of the backup files. Replace `<DATE_TIME>` with the date and time in the name of the backup folder:

    ```bash
    tar -xzvf wazuh-indexer-backup.tar.gz
    cd ~/wazuh_files_backup/<DATE_TIME>
    ```

### Restoring Wazuh indexer files

Perform the following steps to restore the Wazuh indexer files on the new server.

> **Note**: The restored `opensearch.yml` binds the node to the old server's address, and the restored certificates were issued for the old server's hostname and IP addresses, both recorded in `host-info.txt`. This procedure assumes the new server takes them over.

1. Stop the Wazuh indexer to prevent any modifications to the Wazuh indexer files during the restoration process:

    ```bash
    systemctl stop wazuh-indexer
    ```

2. Restore the Wazuh indexer configuration files and change the file permissions and ownership accordingly:

    ```bash
    cp -rp etc/wazuh-indexer/. /etc/wazuh-indexer/
    cp -p usr/lib/sysctl.d/wazuh-indexer.conf /usr/lib/sysctl.d/wazuh-indexer.conf

    chown -R root:wazuh-indexer /etc/wazuh-indexer
    find /etc/wazuh-indexer -type d -exec chmod 750 {} +
    find /etc/wazuh-indexer -type f -exec chmod 640 {} +
    chown root:root /etc/wazuh-indexer/certs/admin.pem /etc/wazuh-indexer/certs/admin-key.pem
    chmod 600 /etc/wazuh-indexer/certs/admin.pem /etc/wazuh-indexer/certs/admin-key.pem
    chown root:root /etc/wazuh-indexer/ca/root-ca.key /etc/wazuh-indexer/export/credentials.env /etc/wazuh-indexer/export/*-client*.pem
    chmod 400 /etc/wazuh-indexer/ca/root-ca.key
    chmod 600 /etc/wazuh-indexer/export/credentials.env /etc/wazuh-indexer/export/*-client*.pem /etc/wazuh-indexer/ca/.wazuh-indexer-bootstrap-ca
    chown root:root /etc/wazuh-indexer/local.env /etc/wazuh-indexer/.wazuh-indexer-keystore 2>/dev/null
    chmod 600 /etc/wazuh-indexer/local.env /etc/wazuh-indexer/.wazuh-indexer-keystore 2>/dev/null
    chown root:root /usr/lib/sysctl.d/wazuh-indexer.conf
    ```

    The configuration directory belongs to root: the Wazuh indexer reads it through its group and writes nothing in it. The admin certificate pair, the CA private key, the published passwords and client pairs, `local.env` and the keystore marker are root's alone; the service refuses to start while `local.env` is readable by anyone else.

    The first command copies everything the backup saved under `/etc/wazuh-indexer/` over the existing files: the certificates, `opensearch.yml`, the JVM options, `log4j2.properties`, the keystore, the security configuration, the plugin configuration directories, the certificate authority in `ca/` and what the node published in `export/`. Copying the contents of the directory (`etc/wazuh-indexer/.`) matters: the package already created these directories on the new server, and `cp -r` of a directory onto an existing one nests the copy inside it (`certs/certs`), where the Wazuh indexer never reads it.

    > **Note:** the sysctl drop-in stays `root`-owned, as the package ships it. It is applied by
    > `systemd-sysctl` as root, so a copy the service account can edit would let that account set
    > kernel parameters.

3. Start the Wazuh indexer service:

    ```bash
    systemctl start wazuh-indexer
    ```

4. Load the restored security configuration into the cluster. Until you do, the restored files under `/etc/wazuh-indexer/opensearch-security/` are not used: the cluster keeps the users, roles and role mappings it already had.

    ```bash
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    ```

    In a multi-node cluster, run it once, on any node, after every node has been restored and started.

    > **Note**: From this point on, the internal users have the passwords they had on the old server, and the restored `/etc/wazuh-indexer/export/credentials.env` lists them. If you did not restore `export/`, the passwords it lists are the ones generated when the package was installed on the new server, and no longer work: the Wazuh Manager and the Wazuh Dashboard on this host read that file, so put the old server's passwords there before installing or starting either of them.

5. Clear the backup files to free up space:

    ```bash
    rm -rf ~/wazuh_files_backup/<DATE_TIME>
    rm -f /wazuh-indexer-backup.tar.gz
    ```
