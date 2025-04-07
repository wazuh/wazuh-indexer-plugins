# Uninstall

>**Note** You need root user privileges to run all the commands described below.

## Yum

```bash
yum remove wazuh-indexer -y
rm -rf /var/lib/wazuh-indexer/
rm -rf /usr/share/wazuh-indexer/
rm -rf /etc/wazuh-indexer/
```

## APT

```bash
apt-get remove --purge wazuh-indexer -y
```
