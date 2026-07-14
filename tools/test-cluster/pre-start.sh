#!/bin/bash

# Workaround to keep the config.yml file as the assistant dumbly removes it.
cp config.yml config.yml.bak

if [ -f "wazuh-install-files.tar" ]; then
    rm -f wazuh-install-files.tar
fi

echo "[INFO] Downloading the installation assistant..."
wget -O wazuh-install.sh https://packages-staging.xdrsiem.wazuh.info/nightly/5.0.0/installation-assistant/wazuh-install-5.0.0-latest.sh

echo "[INFO] Generating config files..."
bash wazuh-install.sh --generate-config-files || exit 1

if [ -f "wazuh-install-files.tar" ]; then
    echo "[INFO] Setup complete."
    mv config.yml.bak config.yml
    chmod +r wazuh-install-files.tar
    chown "$1:$1" wazuh-install-files.tar config.yml
else
    echo "[ERROR] Setup failed. Please check the output above for errors."
    mv config.yml.bak config.yml
    chown "$1:$1" config.yml
    exit 1
fi
