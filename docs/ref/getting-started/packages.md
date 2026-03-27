# Packages

Wazuh Indexer packages can be downloaded from the internal S3 buckets though the following links. Note these links are placeholders, and that you need to replace the `RELEASE_SERIES`, the `VERSION` and the `REVISION` with the appropriate values.

```
wazuh_indexer_aarch64_rpm: "https://packages-staging.xdrsiem.wazuh.info/pre-release/<RELEASE_SERIES>/yum/wazuh-indexer-<VERSION>-<REVISION>.aarch64.rpm"
wazuh_indexer_amd64_deb: "https://packages-staging.xdrsiem.wazuh.info/pre-release/<RELEASE_SERIES>/apt/pool/main/w/wazuh-indexer/wazuh-indexer_<VERSION>-<REVISION>_amd64.deb"
wazuh_indexer_arm64_deb: "https://packages-staging.xdrsiem.wazuh.info/pre-release/<RELEASE_SERIES>/apt/pool/main/w/wazuh-indexer/wazuh-indexer_<VERSION>-<REVISION>_arm64.deb"
wazuh_indexer_x86_64_rpm: "https://packages-staging.xdrsiem.wazuh.info/pre-release/<RELEASE_SERIES>/yum/wazuh-indexer-<VERSION>-<REVISION>.x86_64.rpm"
```

**Examples**
```
wazuh_indexer_aarch64_rpm: "https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-indexer-5.0.0-alpha99.aarch64.rpm"
wazuh_indexer_amd64_deb: "https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0-alpha99_amd64.deb"
wazuh_indexer_arm64_deb: "https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/apt/pool/main/w/wazuh-indexer/wazuh-indexer_5.0.0-alpha99_arm64.deb"
wazuh_indexer_x86_64_rpm: "https://packages-staging.xdrsiem.wazuh.info/pre-release/5.x/yum/wazuh-indexer-5.0.0-alpha99.x86_64.rpm"
```

## Compatibility

Please refer to [this section](../compatibility.md) for information pertaining to compatibility.
