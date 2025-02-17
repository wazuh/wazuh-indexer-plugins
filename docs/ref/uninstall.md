# Uninstall
You can uninstall all the Wazuh central components using the [Wazuh installation assistant](https://packages.wazuh.com/4.10/wazuh-install.sh).

Run the assistant with the option `-u` or `--uninstall` as follows:

```
sudo bash wazuh-install.sh --uninstall
```

This will remove the Wazuh indexer, the Wazuh server, and the Wazuh dashboard.

If you want to uninstall the Wazuh indexer, follow the instructions below.

<div style="border-left: 4px solid #499cfe; background-color:rgba(73, 156, 254, .1); padding: 10px;">
    <strong>Note</strong> You need root user privileges to run all the commands described below.
</div>

---
**Yum**
```
yum remove wazuh-indexer -y
rm -rf /var/lib/wazuh-indexer/
rm -rf /usr/share/wazuh-indexer/
rm -rf /etc/wazuh-indexer/
```

---
**APT**
```
apt-get remove --purge wazuh-indexer -y
```