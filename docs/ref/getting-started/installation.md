## Installation

> **Note**:
> This documentation assumes you are already provisioned with a wazuh-indexer package through any of the possible methods:
>   - [Local package generation](../../dev/build-packages.md) (recommended).
>   - [GH Workflows artifacts](https://github.com/wazuh/wazuh-indexer/actions).
>   - [Staging S3 buckets](./packages.md)

### Installing the Wazuh indexer step by step

Install and configure the Wazuh indexer as a single-node or multi-node cluster, following step-by-step instructions. To move an existing 4.x deployment to 5.x, see [Migration guide](../../guide/migration/index.md). The installation process is divided into three stages.

1. Certificates creation

2. Nodes installation

3. Cluster initialization

> **Note**: You need root user privileges to run all the commands described below.

### 1. Certificates

The Wazuh indexer issues its own certificates when the package is installed, signed by a certificate authority it creates in `/etc/wazuh-indexer/ca/`. **A single-node deployment needs nothing from this stage** — skip to [Nodes installation](#2-nodes-installation).

Every node of a cluster must trust the same authority, and the authority each package creates is local to its own host. For a multi-node cluster, either stage one authority on every node before installing the package, or generate one set of certificates for the whole cluster and distribute it, as described below.

To stage the authority, install the package on the first node, then copy its `/etc/wazuh-indexer/ca/root-ca.pem` and `/etc/wazuh-indexer/ca/root-ca.key` into `/etc/wazuh-indexer/ca/` on each other node before installing the package there: the directory owned by `root:root` with mode `750`, the certificate `640` and the key `400`. Each package then issues its own certificates from that authority, and the first node's `/etc/wazuh-indexer/export/credentials.env` holds the passwords of the whole cluster once the security configuration is loaded. Add every node's Distinguished Name to `plugins.security.nodes_dn` on every node, as described in [Configuring the Wazuh indexer](#configuring-the-wazuh-indexer).

The same applies if you bring certificates from your own PKI: before installing the package, stage each node's pair, the admin pair and the CA that issued them, as described in [On every other Wazuh indexer node](#on-every-other-wazuh-indexer-node). The installation then uses them and creates no authority of its own. To have it also issue the client pairs of the Wazuh manager and the Wazuh dashboard from that CA, stage the CA's key as well, as `/etc/wazuh-indexer/ca/root-ca.key` with mode `400`.

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

    On the node that generated them, replace the certificates the package issued with this node's pair. On every other Wazuh indexer node, stage that node's pair before installing the package. See [Deploying certificates](#deploying-certificates).

### 2. Nodes installation

#### Installing package dependencies

Install the following packages if missing:

##### yum

```bash
yum install iproute openssl shadow-utils
```

##### apt

```bash
apt-get install iproute2 openssl passwd
```

#### Supplying your own passwords

The installation generates a password for each internal user, but only for the users it does not already find a password for. To choose them yourself, write them to `/etc/wazuh-indexer/local.env` before installing the package.

That file is yours: the package reads it and never writes it. It holds passwords, so it must be owned by root with mode `600`, and the installation refuses to read it otherwise:

```bash
install -d -m 0750 -o root -g root /etc/wazuh-indexer
cat > /etc/wazuh-indexer/local.env <<'EOF'
WAZUH_INDEXER_ADMIN_PASSWORD=<admin-password>
WAZUH_INDEXER_KIBANASERVER_PASSWORD=<kibanaserver-password>
WAZUH_INDEXER_MANAGER_PASSWORD=<wazuh-manager-password>
EOF
chmod 600 /etc/wazuh-indexer/local.env
```

Set as many or as few as you like: any key you leave out is generated. Each password must have 12 to 64 characters from `A-Z a-z 0-9 . , _ + : @ % ^ = ~ -`, with at least one uppercase letter, one lowercase letter, one digit and one symbol. A value that does not meet the rule is never replaced silently — the service refuses to start and names the key in its log.

The same file takes `WAZUH_INDEXER_CERT_SANS`, a comma-separated list of the names and addresses to put on the node's certificate (for example `DNS:node-1.example.com,IP:10.0.0.1`) instead of the ones the installation discovers; `localhost` and the loopback addresses are always added.

#### Installing the Wazuh indexer package

If this node uses certificates generated in advance and is not the node that generated them, stage them first, as described in [On every other Wazuh indexer node](#on-every-other-wazuh-indexer-node).

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

The installation publishes one password per internal user in `/etc/wazuh-indexer/export/credentials.env`, readable only by root — the ones it generated, and the ones it was given:

```bash
cat /etc/wazuh-indexer/export/credentials.env
```

```
# Published by wazuh-indexer for the manager and the dashboard on this host. Do not edit.
WAZUH_INDEXER_ADMIN_PASSWORD=...
WAZUH_INDEXER_KIBANASERVER_PASSWORD=...
WAZUH_INDEXER_MANAGER_PASSWORD=...
```

Values are written as they are, without quotes — see [About the examples](../index.md#about-the-examples). `admin` is the login for the Wazuh dashboard and the Wazuh indexer API; `kibanaserver` and `wazuh-manager` are the accounts the Wazuh dashboard and the Wazuh manager connect with. The directory also holds `ca.pem`, the certificate of the authority this node's certificates are issued from, and the client certificate pairs that authority issued for the Wazuh manager (`manager-client.pem`, `manager-client-key.pem`) and the Wazuh dashboard (`dashboard-client.pem`, `dashboard-client-key.pem`), readable only by root. A client pair identifies the component to the Wazuh indexer; it grants no permission by itself, and each component keeps authenticating with its password.

The Wazuh Manager and the Wazuh Dashboard installed on the same host read `export/` when they are installed and at every start, so keep it. On another host, copy the values they need into their own `local.env` and `certs/` before installing them: `WAZUH_INDEXER_MANAGER_PASSWORD`, `ca.pem` and the manager client pair for the manager, `WAZUH_INDEXER_KIBANASERVER_PASSWORD` and `ca.pem` for the dashboard. The client pair of any Wazuh indexer node of the cluster serves: it names no host.

Passwords are generated once. Reinstalling, restarting or upgrading the Wazuh indexer does not change them. To change one afterwards, use the passwords tool, which also ships with the package. It prompts for the new password twice and echoes nothing, so the password does not reach your shell history:

```bash
/usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh -u admin -p
```

A new password must meet the same rule as a supplied one — see [Supplying your own passwords](#supplying-your-own-passwords).

When the standard input is not a terminal the tool reads the password from it instead of prompting, which is how a script sets one:

```bash
printf '%s' '<new-password>' | /usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh -u admin -p
```

`-p` takes no value: the tool prompts for the new password, or reads it from standard input when that is not a terminal, for example `printf '%s\n' '<new-password>' | /usr/share/wazuh-indexer/tools/wazuh-passwords-tool.sh -u admin -p`. Without `-p`, the tool generates a random password. Either way the new password is published in `/etc/wazuh-indexer/export/credentials.env`.

#### Configuring the Wazuh indexer

Edit the `/etc/wazuh-indexer/opensearch.yml` configuration file and replace the values in steps (a) to (e). Then set the JVM heap size in `/etc/wazuh-indexer/jvm.options`, as described in step (f).

The package ships a working single-node configuration: one node named `node-1`, listening on all interfaces (`0.0.0.0`). On a single node, steps (a) to (e) are optional: apply (a) to listen on a specific address, and (b) together with (c) to rename the node. Step (f) applies to every node, including a single node, because the package starts with a 1 GB heap. A multi-node cluster needs all six steps, on every node.

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

  f. **JVM heap size**: Set it in `/etc/wazuh-indexer/jvm.options`, before the first start. The package sets it to 1 GB. Use half of the system RAM when the Wazuh indexer is alone on the host, or a quarter when the Wazuh manager or the Wazuh dashboard runs on the same host. Set the initial (`-Xms`) and maximum (`-Xmx`) heap size to the same value. For example, on a dedicated node with 8 GB of RAM:

  ```ini
  -Xms4g
  -Xmx4g
  ```

  For a size that is not a whole number of gigabytes, use megabytes, for example `-Xms1536m` and `-Xmx1536m`. See [JVM heap size](../../ref/configuration/index.md#jvm-heap-size) for the sizing limits, and [Memory locking](../../ref/configuration/index.md#memory-locking) for the memory the node needs beyond the heap.

#### Deploying certificates

> **Note**: This step applies only if you generated the certificates in advance, as described in [Certificates](#1-certificates). A single-node deployment already has the certificates the package issued.
>
> Make sure that a copy of the `wazuh-certificates.tar` file, created during the initial configuration step, is placed in your working directory.

The installation takes in certificates only when the package is installed: certificates replaced afterwards are used, but their authority is not published to the Wazuh manager and the Wazuh dashboard on the host. The certificates tool signs with the authority of the node it runs on, so that node can replace its pair afterwards, while every other node must have its pair and that authority staged before the package is installed.

In the commands below, replace `<INDEXER_NODE_NAME>` with the name of the Wazuh indexer node you are configuring as defined in `config.yml`. For example, `node-1`.

```bash
NODE_NAME=<INDEXER_NODE_NAME>
```

##### On the node that generated the certificates

The package is already installed here. Replace the pair it issued:

```bash
mkdir -p /etc/wazuh-indexer/certs
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv -f /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv -f /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
chown -R root:wazuh-indexer /etc/wazuh-indexer/certs
chmod 750 /etc/wazuh-indexer/certs
chmod 640 /etc/wazuh-indexer/certs/*
chown root:root /etc/wazuh-indexer/certs/admin.pem /etc/wazuh-indexer/certs/admin-key.pem
chmod 600 /etc/wazuh-indexer/certs/admin.pem /etc/wazuh-indexer/certs/admin-key.pem
```

`mv -f` is required: the package already issued `indexer.pem` and `indexer-key.pem`, and the cluster's pair must replace them. The files belong to root: the Wazuh indexer reads its own pair and the trust anchor through its group, and the admin pair is used by `indexer-security-init.sh` alone, which runs as root. A pair owned by the `wazuh-indexer` user is refused when the service starts.

The certificates tool and the package issue certificates with the same subject format, so the `plugins.security.authcz.admin_dn` the installation wrote into `/etc/wazuh-indexer/opensearch.yml` stays valid. The node Distinguished Name it wrote stays valid only if the host's short name matches the node name in `config.yml`, because the package uses the hostname as `CN` and the certificates tool uses the node name.

##### On every other Wazuh indexer node

Run these commands before installing the package. They stage this node's pair, the admin pair and the authority that issued them, `root-ca.pem`, both beside the pair and in `/etc/wazuh-indexer/ca/`:

```bash
install -d -m 750 /etc/wazuh-indexer /etc/wazuh-indexer/certs /etc/wazuh-indexer/ca
tar -xf ./wazuh-certificates.tar -C /etc/wazuh-indexer/certs/ ./$NODE_NAME.pem ./$NODE_NAME-key.pem ./admin.pem ./admin-key.pem ./root-ca.pem
mv /etc/wazuh-indexer/certs/$NODE_NAME.pem /etc/wazuh-indexer/certs/indexer.pem
mv /etc/wazuh-indexer/certs/$NODE_NAME-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
cp /etc/wazuh-indexer/certs/root-ca.pem /etc/wazuh-indexer/ca/root-ca.pem
chmod 640 /etc/wazuh-indexer/certs/* /etc/wazuh-indexer/ca/root-ca.pem
chmod 600 /etc/wazuh-indexer/certs/admin.pem /etc/wazuh-indexer/certs/admin-key.pem
```

The installation gives the node's pair and the authority to the `wazuh-indexer` group, which does not exist before it, and writes the subjects of the pair and the admin pair into `plugins.security.nodes_dn` and `plugins.security.authcz.admin_dn`. It also checks that the authority issued the pair, and when it did not, the service does not start:

```
resolve-credentials: the certificate pair in /etc/wazuh-indexer/certs was not issued by /etc/wazuh-indexer/ca/root-ca.pem
```

The installation publishes the authority as `/etc/wazuh-indexer/export/ca.pem` for the Wazuh manager and the Wazuh dashboard on this host. Its key stays on the node that generated the certificates, so this node issues no client pairs for them: copy the client pairs from `/etc/wazuh-indexer/export/` on that node, as described in [Retrieving the generated credentials](#retrieving-the-generated-credentials).

##### Distinguished Names

Make sure `plugins.security.nodes_dn` lists every node, as described in [Configuring the Wazuh indexer](#configuring-the-wazuh-indexer): the installation writes only this node's subject. To print the subject of a certificate in the form these settings expect, run:

```bash
openssl x509 -noout -subject -nameopt RFC2253 -in /etc/wazuh-indexer/certs/indexer.pem
```

`indexer-security-init.sh` warns when the admin certificate is not among the subjects in `plugins.security.authcz.admin_dn`.

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

1. Replace `$WAZUH_INDEXER_IP_ADDRESS` and run the following commands to confirm that the installation is successful. `$WAZUH_INDEXER_ADMIN_PASSWORD` is the `admin` password from `/etc/wazuh-indexer/export/credentials.env`. Load it with `WAZUH_INDEXER_ADMIN_PASSWORD=$(sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh-indexer/export/credentials.env | cut -d= -f2- | tail -n 1)`.

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

2. Replace `$WAZUH_INDEXER_IP_ADDRESS` and run the following command to check if the single-node or multi-node cluster is working correctly.

    ```bash
    curl -sk -u admin:$WAZUH_INDEXER_ADMIN_PASSWORD -X GET "https://$WAZUH_INDEXER_IP_ADDRESS:9200/_cat/nodes?v"
    ```
