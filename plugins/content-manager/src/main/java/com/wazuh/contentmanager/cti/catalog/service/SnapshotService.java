package com.wazuh.contentmanager.cti.catalog.service;

import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

public interface SnapshotService {

    void initialize(RemoteConsumer consumer);
}
