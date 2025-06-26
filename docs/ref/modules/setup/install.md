# Install

To manually install the setup plugin using a built package you may follow the next steps.

>**Note** You need root user privileges to run the commands.

1. Navigate to the directory where the plugin `.zip` file is located.

2. Run the following command to install the plugin:

    ```bash
    /usr/share/wazuh-indexer/bin/opensearch-plugin install file://$(pwd)/wazuh-indexer-setup-5.0.0.0.zip
    ```

Once installed, restart the Wazuh Indexer service to apply changes.
