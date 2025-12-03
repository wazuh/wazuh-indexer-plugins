package com.wazuh.contentmanager.cti.catalog.service;

import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

/**
 * Service interface for managing CTI snapshots.
 * Defines the contract for initializing consumers from remote snapshots.
 */
public interface UpdateService {

    void update(long fromOffset, long toOffset);
}
