# Uninstall

> **Note:** You need root user privileges to run all the commands described below.

## Red Hat-based platforms

```bash
sudo rpm -e wazuh-indexer
sudo rm -rf /var/lib/wazuh-indexer/
sudo rm -rf /usr/share/wazuh-indexer/
sudo rm -rf /etc/wazuh-indexer/
```

## Debian-based platforms

```bash
sudo dpkg --purge wazuh-indexer
sudo rm -rf /var/lib/wazuh-indexer/
sudo rm -rf /usr/share/wazuh-indexer/
sudo rm -rf /etc/wazuh-indexer/
```
