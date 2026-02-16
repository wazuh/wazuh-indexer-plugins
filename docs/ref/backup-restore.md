# Backup and restore

In this section you can find instructions on how to create and restore a backup of your Wazuh Indexer key files, preserving file permissions, ownership, and path. Later, you can move this folder contents back to the corresponding location to restore your certificates and configurations. Backing up these files is useful in cases such as moving your Wazuh installation to another system.

> **Note**: This backup only restores the configuration files, not the data. To backup data stored in the indexer, use [snapshots](https://docs.opensearch.org/3.3/tuning-your-cluster/availability-and-recovery/snapshots/snapshot-restore/).

## Creating a backup

To create a backup of the Wazuh indexer, follow these steps. Repeat them on every cluster node you want to back up.

> **Note**: You need root user privileges to run all the commands described below.

### Preparing the backup

1. Create the destination folder to store the files. For version control, add the date and time of the backup to the name of the folder.

    ```bash
    bkp_folder=~/wazuh_files_backup/$(date +%F_%H:%M)
    mkdir -p $bkp_folder && echo $bkp_folder
    ```

2. Save the host information.

    ```bash
    cat /etc/*release* > $bkp_folder/host-info.txt
    echo -e "\n$(hostname): $(hostname -I)" >> $bkp_folder/host-info.txt
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
/etc/wazuh-indexer/opensearch-observability/ \
/etc/wazuh-indexer/opensearch-reports-scheduler/ \
/etc/wazuh-indexer/opensearch-security/ \
/usr/lib/sysctl.d/wazuh-indexer.conf $bkp_folder
```

Compress the files and transfer them to the new server:

    ```bash
    tar -cvzf wazuh_central_components.tar.gz ~/wazuh_files_backup/
    ```

## Restoring Wazuh indexer from backup

This guide explains how to restore a backup of your configuration files.

>**Note**: This guide is designed specifically for restoration from a backup of the same version.

---

>**Note**: For a multi-node setup, there should be a backup file for each node within the cluster. You need root user privileges to execute the commands below.

#### Preparing the data restoration

1. In the new node, move the compressed backup file to the root `/` directory:

    ```bash
    mv wazuh_central_components.tar.gz /
    cd /
    ```

2. Decompress the backup files and change the current working directory to the directory based on the date and time of the backup files:

    ```bash
    tar -xzvf wazuh_central_components.tar.gz
    cd ~/wazuh_files_backup/<DATE_TIME>
    ```

#### Restoring Wazuh indexer files

Perform the following steps to restore the Wazuh indexer files on the new server.

1. Stop the Wazuh indexer to prevent any modifications to the Wazuh indexer files during the restoration process:

    ```bash
    systemctl stop wazuh-indexer
    ```

2. Restore the Wazuh indexer configuration files and change the file permissions and ownerships accordingly:

    ```bash
    sudo cp etc/wazuh-indexer/jvm.options /etc/wazuh-indexer/jvm.options
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/jvm.options
    sudo cp -r etc/wazuh-indexer/jvm.options.d/* /etc/wazuh-indexer/jvm.options.d/
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/jvm.options.d
    sudo cp etc/wazuh-indexer/log4j2.properties /etc/wazuh-indexer/log4j2.properties
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/log4j2.properties
    sudo cp etc/wazuh-indexer/opensearch.keystore /etc/wazuh-indexer/opensearch.keystore
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.keystore
    sudo cp -r etc/wazuh-indexer/opensearch-observability/* /etc/wazuh-indexer/opensearch-observability/
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-observability/
    sudo cp -r etc/wazuh-indexer/opensearch-reports-scheduler/* /etc/wazuh-indexer/opensearch-reports-scheduler/
    chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch-reports-scheduler/
    sudo cp usr/lib/sysctl.d/wazuh-indexer.conf /usr/lib/sysctl.d/wazuh-indexer.conf
    ```

3. Start the Wazuh indexer service:

    ```bash
    systemctl start wazuh-indexer
    ```
