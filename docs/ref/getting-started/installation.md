# Installation

## Installing the Wazuh indexer step by step

Install and configure the Wazuh indexer as a single-node or multi-node cluster following step-by-step instructions. Wazuh indexer is a highly scalable full-text search engine and offers advanced security, alerting, index management, deep performance analysis, and several other features.

The installation process is divided into three stages.

1. Certificates creation

1. Nodes installation

1. Cluster initialization


<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Note</strong> You need root user privileges to run all the commands described below.
</div>

## 1. Certificates creation

### Generating the SSL certificates

1. Download the `wazuh-certs-tool.sh` script and the `config.yml` configuration file. This creates the certificates that encrypt communications between the Wazuh central components.

```
curl -sO https://packages.wazuh.com/4.10/wazuh-certs-tool.sh
curl -sO https://packages.wazuh.com/4.10/config.yml
```

2. Edit `./config.yml` and replace the node names and IP values with the corresponding names and IP addresses. You need to do this for all Wazuh server, Wazuh indexer, and Wazuh dashboard nodes. Add as many node fields as needed.

```bash
nodes:
  # Wazuh indexer nodes
  indexer:
    - name: node-1
      ip: "<indexer-node-ip>"
    #- name: node-2
    #  ip: "<indexer-node-ip>"
    #- name: node-3
    #  ip: "<indexer-node-ip>"

  # Wazuh server nodes
  # If there is more than one Wazuh server
  # node, each one must have a node_type
  server:
    - name: wazuh-1
      ip: "<wazuh-manager-ip>"
    #  node_type: master
    #- name: wazuh-2
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker
    #- name: wazuh-3
    #  ip: "<wazuh-manager-ip>"
    #  node_type: worker

  # Wazuh dashboard nodes
  dashboard:
    - name: dashboard
      ip: "<dashboard-node-ip>"
```

To learn more about how to create and configure the certificates, see the [Certificates deployment](https://documentation.wazuh.com/current/user-manual/wazuh-indexer-cluster/certificate-deployment.html) section.

3. Run `./wazuh-certs-tool.sh` to create the certificates. For a multi-node cluster, these certificates need to be later deployed to all Wazuh instances in your cluster.
``` 
./wazuh-certs-tool.sh -A
```

4. Compress all the necessary files.
```
tar -cvf ./wazuh-certificates.tar -C ./wazuh-certificates/ .
rm -rf ./wazuh-certificates
```

5. Copy the `wazuh-certificates.tar` file to all the nodes, including the Wazuh indexer, Wazuh server, and Wazuh dashboard nodes. This can be done by using the `scp` utility.

## 2. Nodes installation

### Installing package dependencies

1. Install the following packages if missing:

**Yum**                                               
```
yum install coreutils                               
```
---
**APT**
```
apt-get install debconf adduser procps
```

### Adding the Wazuh repository

**Yum**
1. Import the GPG key.
```
rpm --import https://packages.wazuh.com/key/GPG-KEY-WAZUH
```

2. Add the repository.
```
echo -e '[wazuh]\ngpgcheck=1\ngpgkey=https://packages.wazuh.com/key/GPG-KEY-WAZUH\nenabled=1\nname=EL-$releasever - Wazuh\nbaseurl=https://packages.wazuh.com/4.x/yum/\nprotect=1' | tee /etc/yum.repos.d/wazuh.repo
```
---
**APT**
1. Install the following packages if missing.
```
apt-get install gnupg apt-transport-https
```

2. Install the GPG key.
```
curl -s https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring gnupg-ring:/usr/share/keyrings/wazuh.gpg --import && chmod 644 /usr/share/keyrings/wazuh.gpg
```

3. Add the repository.
```
echo "deb [signed-by=/usr/share/keyrings/wazuh.gpg] https://packages.wazuh.com/4.x/apt/ stable main" | tee -a /etc/apt/sources.list.d/wazuh.list
```

4. Update the packages information.
```
apt-get update
```

### Installing the Wazuh indexer

1. Install the Wazuh indexer package.

**Yum**
```
yum -y install wazuh-indexer
```
---
**APT**
```
apt-get -y install wazuh-indexer
```

### Configuring the Wazuh indexer


<ol type="1">
<li> Edit the <code>/etc/wazuh-indexer/opensearch.yml</code> configuration file and replace the following values:

<ol type = "a">
    <li> <code>network.host</code>: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and use it as its publish address. Accepts an IP address or a hostname.
    <br><br>
    Use the same node address set in <code>config.yml</code> to create the SSL certificates.</li>
    <br>
    <li> <code>node.name</code>: Name of the Wazuh indexer node as defined in the <code>config.yml</code> file. For example, <code>node-1</code>.</li>
    <br>
    <li> <code>cluster.initial_master_nodes</code>: List of the names of the master-eligible nodes. These names are defined in the <code>config.yml</code> file. Uncomment the <code>node-2</code> and <code>node-3</code> lines, change the names, or add more lines, according to your <code>config.yml</code> definitions.
    <br><br>
    <pre><code>
cluster.initial_master_nodes:
- "node-1"
- "node-2"
- "node-3"
    </code></pre></li>
    <li><code>discovery.seed_hosts</code>: List of the addresses of the master-eligible nodes. Each element can be either an IP address or a hostname. You may leave this setting commented if you are configuring the Wazuh indexer as a single node. For multi-node configurations, uncomment this setting and set the IP addresses of each master-eligible node.
    <pre><code>
discovery.seed_hosts:
 - "10.0.0.1"
 - "10.0.0.2"
 - "10.0.0.3"
    </code></pre><br>
    </li>
    <li><code>plugins.security.nodes_dn</code>: List of the Distinguished Names of the certificates of all the Wazuh indexer cluster nodes. Uncomment the lines for <code>node-2</code> and <code>node-3</code> and change the common names (CN) and values according to your settings and your <code>config.yml</code> definitions.
    <pre><code>
plugins.security.nodes_dn:
- "CN=node-1,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=node-2,OU=Wazuh,O=Wazuh,L=California,C=US"
- "CN=node-3,OU=Wazuh,O=Wazuh,L=California,C=US"
    </code></pre><br>
    </li>
</ol>
</ol>

### Deploying certificates

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Note:</strong> Make sure that a copy of the <code>nazuh-certificates.tar</code> file, created during the initial configuration step, is placed in your working directory.
</div>

1. Run the following commands replacing `<INDEXER_NODE_NAME>` with the name of the Wazuh indexer node you are configuring as defined in `config.yml`. For example, `node-1`. This deploys the SSL certificates to encrypt communications between the Wazuh central components.

```
NODE_NAME=<INDEXER_NODE_NAME>
```

```
mkdir /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -n /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
```

2. **Recommended action**: If no other Wazuh components are going to be installed on this node, remove the `wazuh-certificates.tar` file by running `rm -f ./wazuh-certificates.tar` to increase security.

### Starting the service

1. Enable and start the Wazuh indexer service.

**Systemd**
```
systemctl daemon-reload
systemctl enable wazuh-indexer
systemctl start wazuh-indexer
```
---
**SysV init**

Choose one option according to the operating system used.
<ol type = "a">
    <li>RPM-based operating system:
    <pre><code>
chkconfig --add wazuh-indexer
service wazuh-indexer start
    </code></pre>
    </li>
    <li>Debian-based operating system:
    <pre><code>
update-rc.d wazuh-indexer defaults 95 10
service wazuh-indexer start
    </code></pre>
    </li>
</ol>   

---
Repeat this stage of the installation process for every Wazuh indexer node in your cluster. Then proceed with initializing your single-node or multi-node cluster in the next stage.

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Recommended Action</strong>: Disable Wazuh Updates.<br><br>
    We recommend disabling the Wazuh package repositories after installation to prevent accidental upgrades that could break the environment.
    <br><br>
    Execute the following command to disable the Wazuh repository:<br>
    <strong>Yum</strong><br>
    <code>sed -i "s/^enabled=1/enabled=0/" /etc/yum.repos.d/wazuh.repo</code><br>
    <hr>
    <strong>APT (Debian/Ubuntu)</strong><br>
    <code >sed -i "s/^deb /#deb /" /etc/apt/sources.list.d/wazuh.list<br>
    apt update</code>
</div>

## 3. Cluster initialization

1. Run the Wazuh indexer `indexer-security-init.sh` script on any Wazuh indexer node to load the new certificates information and start the single-node or multi-node cluster.

```
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Note:</strong> You only have to initialize the cluster once, there is no need to run this command on every node.
</div>

### Testing the cluster installation

1. Replace `<WAZUH_INDEXER_IP_ADDRESS>` and run the following commands to confirm that the installation is successful.

```
curl -k -u admin:admin https://<WAZUH_INDEXER_IP_ADRESS>:9200
```
**Output**
```
{
  "name" : "node-1",
  "cluster_name" : "wazuh-cluster",
  "cluster_uuid" : "095jEW-oRJSFKLz5wmo5PA",
  "version" : {
    "number" : "7.10.2",
    "build_type" : "rpm",
    "build_hash" : "db90a415ff2fd428b4f7b3f800a51dc229287cb4",
    "build_date" : "2023-06-03T06:24:25.112415503Z",
    "build_snapshot" : false,
    "lucene_version" : "9.6.0",
    "minimum_wire_compatibility_version" : "7.10.0",
    "minimum_index_compatibility_version" : "7.0.0"
  },
  "tagline" : "The OpenSearch Project: https://opensearch.org/"
}
```

2. Replace `<WAZUH_INDEXER_IP_ADDRESS>` and run the following command to check if the single-node or multi-node cluster is working correctly.

```
curl -k -u admin:admin https://<WAZUH_INDEXER_IP_ADDRESS>:9200/_cat/nodes?v
```

## Next steps
The Wazuh indexer is now successfully installed on your single-node or multi-node cluster, and you can proceed with installing the Wazuh server. To perform this action, see the [Installing the Wazuh server step by step](https://documentation.wazuh.com/current/installation-guide/wazuh-server/step-by-step.html) section.

If you want to uninstall the Wazuh indexer, see [Uninstall the Wazuh indexer](https://documentation.wazuh.com/current/installation-guide/uninstalling-wazuh/central-components.html#uninstall-indexer).