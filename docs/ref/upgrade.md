# Upgrade

This section guides you through the upgrade process of the Wazuh indexer.

## Preparing the upgrade

In case Wazuh is installed in a multi-node cluster configuration, repeat the following steps for every node.

<ol type="1">
    <li> Ensure you have added the Wazuh repository to every Wazuh indexer node before proceeding to perform the upgrade actions.<br>
        <strong>Yum</strong><br>
        <ol type="1">
        <li>Import the GPG key.<br>
        <pre><code>
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
        </code></pre></li>
        <li>Add the repository.<br>
        <pre><code>
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo
        </code></pre></li>
        </ol><hr>
        <strong>APT</strong>
        <ol type ="1">
        <li>Install the following packages if missing.<br>
        <pre><code>
apt-get install gnupg apt-transport-https
        </code></pre></li>
        <li>Install the GPG key.<br>
        <pre><code>
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
        </code></pre>
        <li>Add the repository.<br>
        <pre><code>
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
        </code></pre>
        <li>Update the packages information.<br>
        <pre><code>
apt-get update
        </code></pre>
        </li></ol>
    </li>
    <li> Stop the Filebeat and Wazuh dashboard services if installed in the node.<br>
    <strong>Systemd</strong>
    <pre><code>
systemctl stop filebeat
systemctl stop wazuh-dashboard
    </code></pre>
    <hr>
    <strong>SysV init</strong>
    <pre><code>
service filebeat stop
service wazuh-dashboard stop
    </code></pre>
    </li>
</ol>

## Upgrading the Wazuh indexer

The Wazuh indexer cluster remains operational throughout the upgrade. The rolling upgrade process allows nodes to be updated one at a time, ensuring continuous service availability and minimizing disruptions. The steps detailed in the following sections apply to both single-node and multi-node Wazuh indexer clusters.

### Preparing the Wazuh indexer cluster for upgrade

Perform the following steps on any of the Wazuh indexer nodes replacing `<WAZUH_INDEXER_IP_ADDRESS>`, `<USERNAME>`, and `<PASSWORD>`.

<ol type="1">
    <li> Disable shard replication to prevent shard replicas from being created while Wazuh indexer nodes are being taken offline for the upgrade.
    <pre><code>
curl -X PUT "https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cluster/settings" \
-u <USERNAME>:<PASSWORD> -k -H "Content-Type: application/json" -d '
{
   "persistent": {
      "cluster.routing.allocation.enable": "primaries"
   }
}'
    </code></pre>
    <strong>Output</strong>
    <pre><code>
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
    </code></pre></li>
    <li>Perform a flush operation on the cluster to commit transaction log entries to the index.
    <pre><code>
curl -X POST "https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_flush" -u <USERNAME>:<PASSWORD> -k
    </code></pre>
    <strong>Output</strong>
    <pre><code>
{
   "_shards" : {
      "total" : 19,
      "successful" : 19,
      "failed" : 0
   }
}
    </code></pre></li>
    <li> Run the following command on the Wazuh manager node(s) if running a single-node Wazuh indexer cluster.
    <strong>Systemd</strong>
    <pre><code>
systemctl stop wazuh-manager
    </code></pre>
    <hr>
    <strong>SysV init</strong>
    <pre><code>
service wazuh-manager stop
    </code></pre></li>
</ol>

### Upgrading the Wazuh indexer nodes

Perform the following steps on each Wazuh indexer node to upgrade them. Upgrade nodes with the `cluster_manager` role last to maintain cluster connectivity among online nodes.

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Note:</strong><br>
    You can check the role of Wazuh indexer nodes in the cluster using the following command:<br>
    <pre><code>
curl -k -u &lt;USERNAME&gt;:&lt;PASSWORD&gt; https://&lt;WAZUH_INDEXER_IP_ADDRESS&gt;:9200/_cat/nodes?v
    </code></pre>
</div>

1. Stop the Wazuh indexer service.
    **Systemd**
    ```
    systemctl stop wazuh-indexer
    ```
    ---
    **SysV init**
    ```
    service wazuh-indexer stop
    ```
2. Upgrade the Wazuh indexer to the latest version.
    **Yum**
    ```
    yum upgrade wazuh-indexer
    ```
    ---
    **APT**
    ```
    apt-get install wazuh-indexer
    ```
3. Restart the Wazuh indexer service.
    **Systemd**
    ```
    systemctl daemon-reload
    systemctl enable wazuh-indexer
    systemctl start wazuh-indexer
    ```
    ---
    **SysV init**
    
    Choose one option according to the operating system used.

    a. RPM-based operating system:
    ```
    chkconfig --add wazuh-indexer
    service wazuh-indexer start
    ```

    b. Debian-based operating system:

    ```
    update-rc.d wazuh-indexer defaults 95 10
    service wazuh-indexer start
    ```

Repeat steps 1 to 3 above on all Wazuh indexer nodes before proceeding to the [post-upgrade actions](#post-upgrade-actions).

### Post-upgrade actions

Perform the following steps on any of the Wazuh indexer nodes replacing `<WAZUH_INDEXER_IP_ADDRESS>`, `<USERNAME>`, and `<PASSWORD>`.

1. Check that the newly upgraded Wazuh indexer nodes are in the cluster.
    ```
    curl -k -u <USERNAME>:<PASSWORD> https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
    ```
2. Re-enable shard allocation.
    ```
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
    ```
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
    ```
    curl -k -u <USERNAME>:<PASSWORD> https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
    ```
    **Output**
    ```
    ip         heap.percent ram.percent cpu load_1m load_5m load_15m node.role node.roles                                        cluster_manager name
    172.18.0.3           34          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client -               wazuh2.indexer
    172.18.0.4           21          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client *               wazuh1.indexer
    172.18.0.2           16          86  32    6.67    5.30     2.53 dimr      cluster_manager,data,ingest,remote_cluster_client -               wazuh3.indexer
    ```
4. Run the following command on the Wazuh manager node(s) to start the Wazuh manager service if you stopped it earlier.

    **Systemd**
    ```
    systemctl start wazuh-manager
    ```
    ---
    **SysV init**
    ```
    service wazuh-manager start
    ```

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    Note that the upgrade process doesn't update plugins installed manually. Outdated plugins might cause the upgrade to fail.<br><br>
    1. Run the following command on each Wazuh indexer node to list installed plugins and identify those that require an update:
    <pre><code>
/usr/share/wazuh-indexer/bin/opensearch-plugin list
    </code></pre>
    In the output, plugins that require an update will be labeled as "outdated".<br><br>
    2. Remove the outdated plugins and reinstall the latest version replacing <code>&lt;PLUGIN_NAME&gt;</code>with the name of the plugin:
    <pre><code>
/usr/share/wazuh-indexer/bin/opensearch-plugin remove &lt;PLUGIN_NAME&gt;
/usr/share/wazuh-indexer/bin/opensearch-plugin install &lt;PLUGIN_NAME&gt;
    </code></pre>
</div>