# Wazuh Indexer Reporting Plugin — Development Guide
This document describes how to build a Wazuh Reporting plugin development environment to create and test new features.

## Working from a minimal environment

In order to deploy a minimal environment for developing the reporting plugin just for testing purposes, you must have at least a Wazuh Indexer and a Wazuh Dashboard environment running. Then, you can create your own SMPT server to test the email notifications from the following [Mailpit configuration](https://github.com/wazuh/wazuh-indexer-reporting/tree/main/docs).
To verify everything is working correctly, try generating reports following the [user's guide](../../ref/modules/reporting/usage.md).

## Working from real scenario packages

### Preparing packages

- Wazuh Indexer package (debian package based on OpenSearch 3.1.0). Compiled locally using the [Docker builder](https://github.com/wazuh/wazuh-indexer/tree/main/build-scripts): `bash builder.sh -d deb -a x64`.
- Wazuh Dashboard package (debian package based on OpenSearch 3.1.0). Downloaded from [wazuh-dashboard actions](https://github.com/wazuh/wazuh-dashboard/actions/runs/16009728935).

> Note: To test using RPM packages, update the Vagrant configuration and provisioning scripts accordingly (for example, change `generic/ubuntu2204` to `generic/centos7` in the Vagrantfile and replace Debian-specific installation commands with RPM equivalents).
### Preparing a development environment

Prepare a multi-VM Vagrant environment with the following components:

- Server
  - Wazuh Indexer (including the reporting plugin).
  - Wazuh Dashboard (including the reporting plugin).
- Mailpit
  - Mailpit SMTP server.

File location should be:
```
working-dir/
├── Vagrantfile
├── data/
│   ├── wazuh-indexer_*.deb
│   ├── wazuh-dashboard_*.deb
│   ├── gencerts.sh
│   ├── mailpit.sh
│   └── server.sh
```

**Vagrantfile**

<details><summary>Details</summary>
<p>

```rb
class VagrantPlugins::ProviderVirtualBox::Action::Network
  def dhcp_server_matches_config?(dhcp_server, config)
    true
  end
end

Vagrant.configure("2") do |config|

    config.vm.define "server" do |server|
      server.vm.box = "generic/ubuntu2204"
      server.vm.provider "virtualbox" do |vb|
        vb.memory = "8192"
      end
      # For Hyper-V provider
      #server.vm.provider "hyperv" do |hv|
      #  hv.memory = 8192
      #end
      server.vm.network "private_network", type: "dhcp"
      server.vm.hostname = "rhel-server"
      config.vm.provision "file", source: "data", destination: "/tmp/vagrant_data"

      server.vm.provision "shell", privileged: true, path: "data/server.sh"
    end

    config.vm.define "mailpit" do |mailpit|
      mailpit.vm.box = "generic/ubuntu2204"
      mailpit.vm.provider "virtualbox" do |vb|
        vb.memory = "1024"
      end
      # For Hyper-V provider
      #client.vm.provider "hyperv" do |hv|
      #  hv.memory = 8192
      #end
      mailpit.vm.network "private_network", type: "dhcp"
      mailpit.vm.hostname = "mailpit"

      config.vm.provision "file", source: "data", destination: "/tmp/vagrant_data"

      mailpit.vm.provision "shell", privileged: true, path: "data/mailpit.sh"
    end

end
```
</p>
</details>


**server.sh**
<details><summary>Details</summary>
<p>

```bash
#!/bin/bash

# Install
dpkg -i /tmp/vagrant_data/wazuh-indexer*.deb
dpkg -i /tmp/vagrant_data/wazuh-dashboard*.deb

# Setup

## Create certs
mkdir certs
cd certs || exit 1
bash /tmp/vagrant_data/gencerts.sh .

mkdir -p /etc/wazuh-indexer/certs
cp admin.pem  /etc/wazuh-indexer/certs/admin.pem
cp admin.key /etc/wazuh-indexer/certs/admin-key.pem
cp indexer.pem  /etc/wazuh-indexer/certs/indexer.pem
cp indexer-key.pem /etc/wazuh-indexer/certs/indexer-key.pem
cp ca.pem /etc/wazuh-indexer/certs/root-ca.pem
chown -R wazuh-indexer.wazuh-indexer /etc/wazuh-indexer/certs/

mkdir -p /etc/wazuh-dashboard/certs
cp dashboard.pem  /etc/wazuh-dashboard/certs/dashboard.pem
cp dashboard-key.pem /etc/wazuh-dashboard/certs/dashboard-key.pem
cp ca.pem /etc/wazuh-dashboard/certs/root-ca.pem
chown -R wazuh-dashboard.wazuh-dashboard /etc/wazuh-dashboard/certs/

systemctl daemon-reload

## set up Indexer
systemctl enable wazuh-indexer
systemctl start wazuh-indexer
/usr/share/wazuh-indexer/bin/indexer-security-init.sh

## set up Dashboard
systemctl enable wazuh-dashboard
systemctl start wazuh-dashboard

## enable IPv6
modprobe ipv6
sysctl -w net.ipv6.conf.all.disable_ipv6=0

## turn off firewalld
sudo ufw disable
```
</p>
</details>


**mailpit.sh**
<details><summary>Details</summary>
<p>

```bash
#!/bin/bash

# Install
curl -sOL https://raw.githubusercontent.com/axllent/mailpit/develop/install.sh && INSTALL_PATH=/usr/bin sudo bash ./install.sh

# Setup
## set up Mailpit
useradd -r -s /bin/false mailpit
groupadd -r mailpit
### Create directories
mkdir -p /var/lib/mailpit
chown -R mailpit.mailpit /var/lib/mailpit

### Create password file
mkdir -p /etc/mailpit
echo "admin:$(openssl passwd -apr1 admin)" > /etc/mailpit/passwords
chown -R mailpit.mailpit /var/lib/mailpit

## Create certs
mkdir certs
cd certs || exit 1
bash /tmp/vagrant_data/gencerts.sh .

mkdir -p /etc/mailpit/certs
cp admin.pem  /etc/mailpit/certs/admin.pem
cp admin.key /etc/mailpit/certs/admin-key.pem
cp mailpit.pem  /etc/mailpit/certs/mailpit.pem
cp mailpit-key.pem /etc/mailpit/certs/mailpit-key.pem
cp ca.pem /etc/mailpit/certs/root-ca.pem
chown -R mailpit.mailpit /etc/mailpit/certs/

## enable IPv6
modprobe ipv6
sysctl -w net.ipv6.conf.all.disable_ipv6=0

## turn off firewalld
sudo ufw disable

echo "======================================================"
echo "Start Mailpit with the following command:"
echo ""
echo "mailpit --listen 0.0.0.0:8025 --smtp 0.0.0.0:1025 --database /var/lib/mailpit.db --ui-auth-file /etc/mailpit/passwords --ui-tls-cert /etc/mailpit/certs/admin.pem --ui-tls-key /etc/mailpit/certs/admin-key.pem --smtp-tls-cert /etc/mailpit/certs/mailpit.pem --smtp-tls-key /etc/mailpit/certs/mailpit-key.pem"
echo "======================================================"

# Adding HTTPS: https://mailpit.axllent.org/docs/configuration/http/
# mailpit --ui-tls-cert /path/to/cert.pem --ui-tls-key /path/to/key.pem

# Adding basic authentication: https://mailpit.axllent.org/docs/configuration/passwords/
# mailpit --ui-auth-file /path/to/password-file
```

</p>
</details>

**gencerts.sh**
<details><summary>Details</summary>
<p>

```bash
#!/bin/bash

if [[ $# -ne 1 ]]; then
fs=$(mktemp -d)
else
fs=$1
shift
fi

echo Working directory $fs
cd $fs

if [[ ! -e $fs/cfssl ]]; then
curl -s -L -o $fs/cfssl https://pkg.cfssl.org/R1.2/cfssl_linux-amd64
curl -s -L -o $fs/cfssljson https://pkg.cfssl.org/R1.2/cfssljson_linux-amd64
chmod 755 $fs/cfssl*
fi

cfssl=$fs/cfssl
cfssljson=$fs/cfssljson

if [[ ! -e $fs/ca.pem ]]; then

cat << EOF | $cfssl gencert -initca - | $cfssljson -bare ca -
{
  "CN": "Wazuh",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
  {
    "C": "US",
    "L": "San Francisco",
    "O": "Wazuh",
    "OU": "Wazuh Root CA"
  }
 ]
}
EOF

fi

if [[ ! -e $fs/ca-config.json ]]; then
$cfssl print-defaults config > ca-config.json
fi

gencert_rsa() {
        name=$1
        profile=$2
cat << EOF | $cfssl gencert -ca=ca.pem -ca-key=ca-key.pem -config=ca-config.json -profile=$profile -hostname="$name,127.0.0.1,localhost" - | $cfssljson -bare $name -
{
  "CN": "$i",
  "key": {
    "algo": "rsa",
    "size": 2048
  },
  "names": [
  {
    "C": "US",
    "L": "California",
    "O": "Wazuh",
    "OU": "Wazuh"
  }
  ],
  "hosts": [
    "$i",
    "localhost"
  ]
}
EOF
openssl pkcs8 -topk8 -inform pem -in $name-key.pem -outform pem -nocrypt -out $name.key
}

gencert_ec() {
    openssl ecparam -name secp256k1 -genkey -noout -out jwt-private.pem
    openssl ec -in jwt-private.pem -pubout -out jwt-public.pem
}

hosts=(indexer dashboard mailpit)
for i in "${hosts[@]}"; do
        gencert_rsa $i www
done

users=(admin)
for i in "${users[@]}"; do
        gencert_rsa $i client
done

gencert_ec
```

</p>
</details>

1. Bring up the environment with `vagrant up`. Use the command provided in the console to start mailpit from within its VM. **mailpit** is configured to use TLS and access credentials (`admin:admin`). Use `ip addr` to check for the public IP address given to the VM and use that IP to access mailpit UI (e.g: `https://172.28.128.136:8025/`).
2. Add the username and password for mailpit to the Wazuh Indexer keystore.
    ```bash
    echo "admin" | /usr/share/wazuh-indexer/bin/opensearch-keystore add opensearch.notifications.core.email.mailpit.username
    echo "admin" | /usr/share/wazuh-indexer/bin/opensearch-keystore add opensearch.notifications.core.email.mailpit.password
    chown wazuh-indexer:wazuh-indexer /etc/wazuh-indexer/opensearch.keystore
    ```
3. Ensure `mailpit` is accessible within the `server` VM (e.g `curl https://172.28.128.136:8025 -k -u admin:admin` should return HTML code). If not, add it to the list of known hosts in `/etc/hosts` (e.g `echo "172.28.128.136 mailpit mailpit" >> /etc/hosts`).