# Reference manual

This section contains the Wazuh Indexer reference manual, composed by installation, upgrade, removal, restore and configuration instructions, performance and security recommendations, architecture and API references for each of the modules composing the Wazuh Indexer.

## About the examples

API examples authenticate as `admin` with `$WAZUH_INDEXER_ADMIN_PASSWORD`. That password is generated during installation and is unique to each deployment, so load it into your shell before running them:

```bash
WAZUH_INDEXER_ADMIN_PASSWORD=$(sudo grep '^WAZUH_INDEXER_ADMIN_PASSWORD=' /etc/wazuh/credentials.env | cut -d= -f2-)
```

If you have already removed that file, as recommended once every component is installed, substitute the password directly. See [Retrieving the generated credentials](./getting-started/installation.md#retrieving-the-generated-credentials).
