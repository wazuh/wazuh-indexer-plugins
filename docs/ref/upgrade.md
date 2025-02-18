# Upgrade

This section guides you through the upgrade process of the Wazuh indexer.

## Preparing the upgrade

In case Wazuh is installed in a multi-node cluster configuration, repeat the following steps for every node.

Ensure you have added the Wazuh repository to every Wazuh indexer node before proceeding to perform the upgrade actions.

### Yum

1. Import the GPG key.
    ```bash
    rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
    ```
1. Add the repository.
   ```bash
   echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo
    ```

### APT

1. Install the following packages if missing.
    ```bash 
    apt-get install gnupg apt-transport-https
    ```

1. Install the GPG key.
   ```bash
   curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
   ```

1. Add the repository.
   ```bash
   echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
   ```
1. Update the packages information.
   ```bash
   apt-get update
   ```
     
## Upgrading the Wazuh indexer

The Wazuh indexer cluster remains operational throughout the upgrade. The rolling upgrade process allows nodes to be updated one at a time, ensuring continuous service availability and minimizing disruptions. The steps detailed in the following sections apply to both single-node and multi-node Wazuh indexer clusters.

### Preparing the Wazuh indexer cluster for upgrade

Perform the following steps on any of the Wazuh indexer nodes replacing `<WAZUH_INDEXER_IP_ADDRESS>`, `<USERNAME>`, and `<PASSWORD>`.

1. Disable shard replication to prevent shard replicas from being created while Wazuh indexer nodes are being taken offline for the upgrade.
    ```bash 
    curl -X PUT "https://:9200/_cluster/settings" \
    -u : -k -H "Content-Type: application/json" -d '
    {
    "persistent": {
        "cluster.routing.allocation.enable": "primaries"
    }
    }'
    ```

    **Output**
    ```bash
    {
        "acknowledged" : true,
        "persistent" : {
          "cluster" : {
            "routing" : {
              "allocation" : {
                "enable" : "primaries"
              }
            }
          }
        },
        "transient" : {}
        }
    ```
1. Perform a flush operation on the cluster to commit transaction log entries to the index.
    ```bash
    curl -X POST "https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_flush" -u <USERNAME>:<PASSWORD> -k
    ```

    **Output**
    ```bash
    {
    "_shards" : {
        "total" : 19,
        "successful" : 19,
        "failed" : 0
       }
    }
    ```

### Upgrading the Wazuh indexer nodes

1. Stop the Wazuh indexer service.
   
    ### Systemd

    ```bash
    systemctl stop wazuh-indexer
    ```
    
    ### SysV init

    ```bash
    service wazuh-indexer stop
    ```
2. Upgrade the Wazuh indexer to the latest version.
   
    ### Yum

    ```bash 
    yum upgrade wazuh-indexer
    ```
    
    ### APT

    ```bash
    apt-get install wazuh-indexer
    ```
3. Restart the Wazuh indexer service.
   
    ### Systemd
    ```bash
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer
    ```
    
    ### SysV init
    
    Choose one option according to the operating system used.

    a. RPM-based operating system:
    ```bash 
    chkconfig --add wazuh-indexer
    service wazuh-indexer start
    ```

    b. Debian-based operating system:

    ```bash
    update-rc.d wazuh-indexer defaults 95 10
    service wazuh-indexer start
    ```

Repeat steps 1 to 3 above on all Wazuh indexer nodes before proceeding to the [post-upgrade actions](#post-upgrade-actions).

### Post-upgrade actions

Perform the following steps on any of the Wazuh indexer nodes replacing `<WAZUH_INDEXER_IP_ADDRESS>`, `<USERNAME>`, and `<PASSWORD>`.

1. Check that the newly upgraded Wazuh indexer nodes are in the cluster.
    ```bash
    curl -k -u <USERNAME>:<PASSWORD> https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
    ```
2. Re-enable shard allocation.
    ```bash 
    # curl -X PUT "https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cluster/settings" \
    -u <USERNAME>:<PASSWORD> -k -H "Content-Type: application/json" -d '
    {
        "persistent": {
            "cluster.routing.allocation.enable": "all"
        }
    }
    '
    ```
    **Output**
    ```bash
    {
        "acknowledged" : true,
        "persistent" : {
            "cluster" : {
            "routing" : {
                "allocation" : {
                "enable" : "all"
                }
            }
            }
        },
        "transient" : {}
    }
    ```
3. Check the status of the Wazuh indexer cluster again to see if the shard allocation has finished.
    ```bash
    curl -k -u <USERNAME>:<PASSWORD> https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
    ```
    **Output**
    ```
    ip         heap.percent ram.percent cpu load_1m load_5m load_15m node.role node.roles                                        cluster_manager name
    172.18.0.3           34          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client -               wazuh2.indexer
    172.18.0.4           21          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client *               wazuh1.indexer
    172.18.0.2           16          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client -               wazuh3.indexer
    ```