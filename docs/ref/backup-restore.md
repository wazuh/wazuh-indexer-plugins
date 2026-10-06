# Back up and restore

In this section you can find instructions on how to create and restore a backup of your Wazuh Indexer key files, preserving file permissions, ownership, and path. Later, you can move this folder contents back to the corresponding location to restore your certificates and configurations. Backing up these files is useful in cases such as moving your Wazuh installation to another system.

> **Note**: This backup only restores the configuration files, not the data. To back up data stored in the indexer, use [snapshots](https://docs.opensearch.org/3.6/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/).

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
/usr/lib/sysctl.d/wazuh-indexer.conf $backup_folder
```

If the node has a `/etc/wazuh/ca/` directory, back it up as well. It holds the certificate authority that signed the node's certificates, including its private key when the package created it:

```bash
rsync -aREz /etc/wazuh/ca/ $backup_folder
```

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

    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer
    chmod 500 /etc/wazuh-indexer/certs
    chmod 400 /etc/wazuh-indexer/certs/*
    chown root:root /usr/lib/sysctl.d/wazuh-indexer.conf
    ```

    The first command copies everything the backup saved under `/etc/wazuh-indexer/` over the existing files: the certificates, `opensearch.yml`, the JVM options, `log4j2.properties`, the keystore, the security configuration and the plugin configuration directories. Copying the contents of the directory (`etc/wazuh-indexer/.`) matters: the package already created these directories on the new server, and `cp -r` of a directory onto an existing one nests the copy inside it (`certs/certs`), where the Wazuh indexer never reads it.

    > **Note:** the sysctl drop-in stays `root`-owned, as the package ships it. It is applied by
    > `systemd-sysctl` as root, so a copy the service account can edit would let that account set
    > kernel parameters.

    If the backup contains `etc/wazuh/ca/`, restore it too, so that the certificate authority on the new server is the one that signed the restored certificates:

    ```bash
    cp -rp etc/wazuh/ca/. /etc/wazuh/ca/
    chown -R root:root /etc/wazuh/ca
    ```

3. Start the Wazuh indexer service:

    ```bash
    systemctl start wazuh-indexer
    ```

4. Load the restored security configuration into the cluster. Until you do, the restored files under `/etc/wazuh-indexer/opensearch-security/` are not used: the cluster keeps the users, roles and role mappings it already had.

    ```bash
    /usr/share/wazuh-indexer/bin/indexer-security-init.sh
    ```

    In a multi-node cluster, run it once, on any node, after every node has been restored and started.

    > **Note**: From this point on, the internal users have the passwords they had on the old server. If `/etc/wazuh/credentials.env` exists on the new server, the `WAZUH_INDEXER_*` passwords it lists are the ones generated when the package was installed there, and no longer work. The Wazuh Manager and the Wazuh Dashboard read this file when they are installed, so replace those values with the old server's passwords before installing either of them on this server.

5. Clear the backup files to free up space:

    ```bash
    rm -rf ~/wazuh_files_backup/<DATE_TIME>
    rm -f /wazuh-indexer-backup.tar.gz
    ```
