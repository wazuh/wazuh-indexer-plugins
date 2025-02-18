# Backup and restore

In this section you can find instructions on how to create and restore a backup of your Wazuh installation.

To do this backup, you copy key files to a folder preserving file permissions, ownership, and path. Later, you can move this folder contents back to the corresponding location to restore your Wazuh data, certificates, and configurations. Backing up Wazuh files is useful in cases such as moving your Wazuh installation to another system.

## Creating a backup 
To create a backup of the Wazuh indexer, follow these steps. Repeat them on every cluster node you want to back up.

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Note</strong> You need root user privileges to run all the commands described below.
</div>

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

### Check the backup

Verify that the Wazuh manager is active and list all the backed up files:

**Systemd**

```
systemctl status wazuh-manager
```
---
**SysV init**
```
service wazuh-manager status
```

<br><br>
```bash
find $bkp_folder -type f | sed "s|$bkp_folder/||" | less
```

## Restoring Wazuh indexer from backup

This guide explains how to restore a backup of your Wazuh files, such as logs, and configurations. Restoring Wazuh files can be useful when migrating your Wazuh installation to a different system. To carry out this restoration, you first need to back up the necessary files. The [Creating a backup](#creating-a-backup) documentation provides a guide that you can follow in creating a backup of the Wazuh indexer.

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Note</strong> This guide is designed specifically for restoration from a backup of the same version.
</div>

---

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Note</strong>  For a multi-node setup, there should be a backup file for each node within the cluster. You need root user privileges to execute the commands below.
</div>

### Single-node data restoration
You need to have a new installation of Wazuh. Follow the [Quickstart](https://documentation.wazuh.com/current/quickstart.html) guide to perform a fresh installation of the Wazuh central components on a new server.

The actions below will guide you through the data restoration process for a single-node deployment.

#### Preparing the data restoration
1. Compress the files generated after performing Wazuh files backup and transfer them to the new server:
    ```
    tar -cvzf wazuh_central_components.tar.gz ~/wazuh_files_backup/
    ```
2. Move the compressed file to the root `/` directory of your node:
    ```
    mv wazuh_central_components.tar.gz /
    cd /
    ```
3. Decompress the backup files and change the current working directory to the directory based on the date and time of the backup files:
    ```
    tar -xzvf wazuh_central_components.tar.gz
    cd ~/wazuh_files_backup/<DATE_TIME>
    ```

#### Restoring Wazuh indexer files
Perform the following steps to restore the Wazuh indexer files on the new server.

1. Stop the Wazuh indexer to prevent any modifications to the Wazuh indexer files during the restoration process:
    ```
    systemctl stop wazuh-indexer
    ```
2. Restore the Wazuh indexer configuration files and change the file permissions and ownerships accordingly:
    ```
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
    ```
    systemctl start wazuh-indexer
    ```

### Multi-node data restoration
Perform the actions below to restore the Wazuh indexer on their respective Wazuh nodes.

#### Preparing the data restoration

1. Compress the files generated after performing [Wazuh files backup](#creating-a-backup) and transfer them to the respective new servers:
    ```
    tar -cvzf <SERVER_HOSTNAME>.tar.gz ~/wazuh_files_backup/
    ```

    Where:
    -   `<SERVER_HOSTNAME>` represents the current server name. Consider adding the naming convention, `_indexer`, `_server`, `_dashboard` if the current hostnames don’t specify them.

    <div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
        <strong>Note</strong>  Make sure that Wazuh indexer compressed files are transferred to the new Wazuh indexer nodes, Wazuh server compressed files are transferred to the new Wazuh server nodes, and Wazuh dashboard compressed files are transferred to the new Wazuh dashboard nodes.
    </div>
2. Move the compressed file to the root `/` directory of each node:
    ```
    mv <SERVER_HOSTNAME>.tar.gz /
    cd /
    ```
3. Decompress the backup files and change the current working directory to the directory based on the date and time of the backup files:
    ```
    tar -xzvf <SERVER_HOSTNAME>.tar.gz
    cd ~/wazuh_files_backup/<DATE_TIME>
    ```

#### Restoring Wazuh indexer files

You need to have a new installation of Wazuh indexer. Follow the [Wazuh indexer - Installation guide](https://documentation.wazuh.com/current/installation-guide/wazuh-indexer/index.html) to perform a fresh Wazuh indexer installation.

Perform the following steps on each Wazuh indexer node.

1. Stop the Wazuh indexer to prevent any modification to the Wazuh indexer files during the restore process:
    ```
    systemctl stop wazuh-indexer
    ```
2. Restore the Wazuh indexer configuration files, and change the file permissions and ownerships accordingly:
    ```
    sudo cp etc/wazuh-indexer/jvm.options /etc/wazuh-indexer/jvm.options
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/jvm.options
    sudo cp etc/wazuh-indexer/jvm.options.d /etc/wazuh-indexer/jvm.options.d
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
    ```
    systemctl start wazuh-indexer
    ```

#### Verifying data restoration
Using the Wazuh dashboard, navigate to the Threat Hunting, File Integrity Monitoring, Vulnerability Detection, and any other modules to see if the data is restored successfully.