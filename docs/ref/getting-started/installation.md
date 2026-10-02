## Installation

> **Note**:
> This documentation assumes you are already provisioned with a wazuh-indexer package through any of the possible methods:
>   - [Local package generation](../../dev/build-packages.md) (recommended).
>   - [GH Workflows artifacts](https://github.com/wazuh/wazuh-indexer/actions).
>   - [Staging S3 buckets](./packages.md)

### Installing the Wazuh indexer step by step

Install and configure the Wazuh indexer as a single-node or multi-node cluster, following step-by-step instructions. The installation process is divided into three stages.

1. Certificates creation

2. Nodes installation

3. Cluster initialization

> **Note**: You need root user privileges to run all the commands described below.

### 1. Certificates

The Wazuh indexer issues its own certificates when the package is installed, signed by a certificate authority it creates in `/etc/wazuh/ca/`. **A single-node deployment needs nothing from this stage** — skip to [Nodes installation](#2-nodes-installation).

Every node of a cluster must trust the same authority, and the authority each package creates is local to its own host. For a multi-node cluster, generate one set of certificates for the whole cluster and distribute it, as described below.

The same applies if you bring certificates from your own PKI: place each node's certificate and key in `/etc/wazuh-indexer/certs/` and the trust anchor in `/etc/wazuh/ca/root-ca.pem`.

#### Generating the SSL certificates

The certificates tool ships with the Wazuh indexer package, so install the package on one node first and generate the cluster's certificates from there. Installing does not start the service, so nothing runs before you are ready.

1. Install the Wazuh indexer package on one node, following [Nodes installation](#2-nodes-installation), and stop after the package is installed.

1. Edit `/usr/share/wazuh-indexer/tools/config.yml` and replace the node names and IP values with the corresponding names and IP addresses. You need to do this for all Wazuh Manager, Wazuh indexer, and Wazuh dashboard nodes. Add as many node fields as needed.

    ```yml
    nodes:
      # Wazuh indexer nodes
      indexer:
        - name: node-1
          ip: "<indexer-node-ip>"
        #- name: node-2
        #  ip: "<indexer-node-ip>"
        #- name: node-3
        #  ip: "<indexer-node-ip>"

      # Wazuh manager nodes
      # If there is more than one Wazuh manager
      # node, each one must have a node_type
      manager:
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

1. Run the tool to create the certificates. It reads `config.yml` from beside itself and writes the result to `wazuh-certificates/` in the same directory.

    ```bash
    /usr/share/wazuh-indexer/tools/wazuh-certs-tool.sh -A
    ```

1. Compress all the necessary files.

    ```bash
    cd /usr/share/wazuh-indexer/tools/
    tar -cvf /tmp/wazuh-certificates.tar -C ./wazuh-certificates/ .
    rm -rf ./wazuh-certificates
    ```

1. Copy the `wazuh-certificates.tar` file to all the nodes, including the Wazuh indexer, Wazuh Manager, and Wazuh dashboard nodes. This can be done by using the `scp` utility.

    On the node that generated them, and on every other Wazuh indexer node, replace the certificates the package issued with this node's pair — see [Deploying certificates](#deploying-certificates).

### 2. Nodes installation

#### Installing package dependencies

Install the following packages if missing:

##### yum

```bash
yum install coreutils diffutils hostname iproute openssl procps-ng util-linux
```

##### apt

```bash
apt-get install debconf adduser procps diffutils iproute2 openssl
```

#### Supplying your own passwords

The installation generates a password for each internal user, but only for the users it does not already find a password for. To choose them yourself, write them to `/etc/wazuh/credentials.env` before installing the package.

That file holds every password in the deployment, so it and its directory are root-only, and the installation refuses to read them otherwise:

```bash
install -d -m 0700 -o root -g root /etc/wazuh
cat > /etc/wazuh/credentials.env <<'EOF'
WAZUH_INDEXER_ADMIN_PASSWORD='<admin-password>'
WAZUH_INDEXER_KIBANASERVER_PASSWORD='<kibanaserver-password>'
WAZUH_INDEXER_MANAGER_PASSWORD='<wazuh-manager-password>'
EOF
chmod 600 /etc/wazuh/credentials.env
```

Set as many or as few as you like: any key you leave out is generated. Each password must have 12 to 64 characters from `A-Z a-z 0-9 . , _ + : @ % ^ = ~ -`, with at least one uppercase letter, one lowercase letter, one digit and one symbol. A value that does not meet the rule is never replaced silently — the service refuses to start and names the key in its log.

The installation records what it read in a block of its own at the end of the file, so a password you supplied appears twice: once as you wrote it, and once in that block. The block is what the other components read.

#### Installing the Wazuh indexer package

Replace the file name with that of the package you downloaded. `<ARCH>` is `x86_64` or `aarch64` for RPM packages, and `amd64` or `arm64` for DEB packages. See [Packages](./packages.md).

##### rpm

```bash
rpm -ivh --replacepkgs wazuh-indexer-<VERSION>-<REVISION>.<ARCH>.rpm
```

##### dpkg

```bash
dpkg -i wazuh-indexer_<VERSION>-<REVISION>_<ARCH>.deb
```

#### Retrieving the generated credentials

The installation writes one password per internal user to `/etc/wazuh/credentials.env`, readable only by root — the ones it generated, and the ones it was given:

```bash
cat /etc/wazuh/credentials.env
```

```
# >>> wazuh generated — do not edit <<<
# Editing a value here does not change the deployment.
# To rotate, use wazuh-passwords-tool.sh.
WAZUH_INDEXER_ADMIN_PASSWORD="..."
WAZUH_INDEXER_KIBANASERVER_PASSWORD="..."
WAZUH_INDEXER_MANAGER_PASSWORD="..."
# >>> end wazuh generated <<<
```

The Wazuh Manager and the Wazuh Dashboard read this file when **they** are installed, so keep it until every component is installed and running. Delete it afterwards — it holds every password in the deployment in plain text:

```bash
rm /etc/wazuh/credentials.env
```

Passwords are generated once. Reinstalling, restarting or upgrading the Wazuh indexer does not change them, and neither does removing this file. To change one afterwards, use the passwords tool, which also ships with the package. It prompts for the new password twice and echoes nothing, so the password does not reach your shell history:

```bash
/usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh -u admin -p
```

A new password must meet the same rule as a supplied one — see [Supplying your own passwords](#supplying-your-own-passwords).

When the standard input is not a terminal the tool reads the password from it instead of prompting, which is how a script sets one:

```bash
printf '%s' '<new-password>' | /usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh -u admin -p
```

`-p` takes no value: the tool prompts for the new password, or reads it from standard input when that is not a terminal, for example `printf '%s\n' '<new-password>' | /usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh -u admin -p`. Without `-p`, the tool generates a random password and saves it to `/etc/wazuh/credentials.env`.

#### Configuring the Wazuh indexer

Edit the `/etc/wazuh-indexer/opensearch.yml` configuration file and replace the following values.

The package ships a working single-node configuration: one node named `node-1`, listening on all interfaces (`0.0.0.0`). On a single node every step is optional: apply (a) to listen on a specific address, and (b) together with (c) to rename the node. A multi-node cluster needs all five steps, on every node.

  a. **`network.host`**: Sets the address of this node for both HTTP and transport traffic. The node will bind to this address and use it as its publish address. Accepts an IP address or a hostname.
  On a multi-node cluster, use the same node address set in `config.yml` to create the SSL certificates.

  b. **`node.name`**: Name of the Wazuh indexer node as defined in the `config.yml` file. For example, `node-1`. If you change it on a single node, change `cluster.initial_cluster_manager_nodes` to match.

  c. **`cluster.initial_cluster_manager_nodes`**: List of the names of the master-eligible nodes. These names are defined in the `config.yml` file. A single node lists only its own `node.name`. For a multi-node cluster, uncomment the `node-2` and `node-3` lines, change the names, or add more lines, according to your `config.yml` definitions.

  ```yml
  cluster.initial_cluster_manager_nodes:
  - "node-1"
  - "node-2"
  - "node-3"
  ```

  d. **`discovery.seed_hosts`**: List of the addresses of the master-eligible nodes. Each element can be either an IP address or a hostname. You may leave this setting commented if you are configuring the Wazuh indexer as a single node. For multi-node configurations, uncomment this setting and set the IP addresses of each master-eligible node.

  ```yml
  discovery.seed_hosts:
  - "10.0.0.1"
  - "10.0.0.2"
  - "10.0.0.3"
  ```

  e. **`plugins.security.nodes_dn`**: List of the Distinguished Names of the certificates of all the Wazuh indexer cluster nodes. The installation writes the Distinguished Name of the certificate the package issued for this node, so a single node needs no change. For a multi-node cluster, list one line per node with the subjects of the certificates you deploy in [Deploying certificates](#deploying-certificates). The certificates tool issues them with the node name from `config.yml` as `CN`, and the Security plugin compares each entry as a string, so keep this order:

  ```yml
  plugins.security.nodes_dn:
  - "C=US,L=California,O=Wazuh,OU=Wazuh,CN=node-1"
  - "C=US,L=California,O=Wazuh,OU=Wazuh,CN=node-2"
  - "C=US,L=California,O=Wazuh,OU=Wazuh,CN=node-3"
  ```

#### Deploying certificates

> **Note**: This step applies only if you generated the certificates in advance, as described in [Certificates](#1-certificates). A single-node deployment already has the certificates the package issued.
>
> Make sure that a copy of the `wazuh-certificates.tar` file, created during the initial configuration step, is placed in your working directory.

Run the following commands, replacing `<INDEXER_NODE_NAME>` with the name of the Wazuh indexer node you are configuring as defined in `config.yml`. For example, `node-1`. This deploys the SSL certificates to encrypt communications between the Wazuh central components.

```bash
NODE_NAME=<INDEXER_NODE_NAME>
```

```bash
mkdir -p /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv -f /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -f /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chmod 500 /etc/wazuh-indexer/certs
chmod 400 /etc/wazuh-indexer/certs/*
chown -R wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/certs
```

`mv -f` is required: the package already issued `indexer.pem` and `indexer-key.pem`, and the cluster's pair must replace them.

The certificates tool and the package issue certificates with the same subject format, so the `plugins.security.authcz.admin_dn` the installation wrote into `/etc/wazuh-indexer/opensearch.yml` stays valid. The node Distinguished Name it wrote stays valid only if the host's short name matches the node name in `config.yml`, because the package uses the hostname as `CN` and the certificates tool uses the node name. Make sure `plugins.security.nodes_dn` lists every node, as described in [Configuring the Wazuh indexer](#configuring-the-wazuh-indexer). To print the subject of a certificate in the form these settings expect, run:

```bash
openssl x509 -noout -subject -nameopt RFC2253 -in /etc/wazuh-indexer/certs/indexer.pem
```

If you deploy certificates from your own PKI instead, set `plugins.security.nodes_dn` and `plugins.security.authcz.admin_dn` to the subjects of the certificates you deployed; `indexer-security-init.sh` warns when the admin certificate is not among them.

#### Set up Wazuh Indexer in your environment

Follow the instructions in the [Configuration](../../ref/configuration/index.md) section to set up Wazuh Indexer in your environment.

{{#include ../../ref/modules/content-manager/configuration.md:offline-config}}

#### Starting the service

Enable and start the Wazuh indexer service. The installation does not start it, and it does not start at boot until it is enabled. The package reloads the service manager itself, so no `systemctl daemon-reload` is needed here.

##### Systemd

```bash
systemctl enable --now wazuh-indexer
```

---

##### SysV

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

---

Repeat this stage of the installation process for every Wazuh indexer node in your cluster. Then proceed with initializing your single-node or multi-node cluster in the next stage.

### 3. Cluster initialization

Run the Wazuh indexer `indexer-security-init.sh` script on any Wazuh indexer node to load the new certificates information and start the single-node or multi-node cluster.

```bash
/usr/share/wazuh-indexer/bin/indexer-security-init.sh
```

> **Note**: You only have to initialize the cluster once, there is no need to run this command on every node.

#### Testing the cluster installation

1. Replace `$WAZUH_INDEXER_IP_ADDRESS` and run the following commands to confirm that the installation is successful. `$WAZUH_INDEXER_ADMIN_PASSWORD` is the `admin` password from `/etc/wazuh/credentials.env`, which `source /etc/wazuh/credentials.env` loads into a root shell. See [Retrieving the generated credentials](#retrieving-the-generated-credentials).

    ```bash
    curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X GET "https://$WAZUH_INDEXER_IP_ADDRESS:9200"
    ```

    **Output**

    ```json
    {
      "name" : "node-1",
      "cluster_name" : "wazuh-cluster",
      "cluster_uuid" : "lEzYZtwXTYaGiSAdbcqQmQ",
      "version" : {
        "distribution" : "opensearch",
        "number" : "3.6.0",
        "build_type" : "deb",
        "build_hash" : "1b0a897cd71105595b450b48b591581865f8b46b",
        "build_date" : "2026-10-01T01:45:08.798733103Z",
        "build_snapshot" : false,
        "lucene_version" : "10.4.0",
        "minimum_wire_compatibility_version" : "2.19.0",
        "minimum_index_compatibility_version" : "2.0.0"
      },
      "tagline" : "The OpenSearch Project: https://opensearch.org/"
    }
    ```

1. Replace `$WAZUH_INDEXER_IP_ADDRESS` and run the following command to check if the single-node or multi-node cluster is working correctly.

    ```bash
    curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X GET "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cat/nodes?v"
    ```
