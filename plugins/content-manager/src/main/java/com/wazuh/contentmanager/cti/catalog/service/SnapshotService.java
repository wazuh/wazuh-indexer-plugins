package com.wazuh.contentmanager.cti.catalog.service;

import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

/**
 * Service interface for managing CTI snapshots.
 * Defines the contract for initializing consumers from remote snapshots.
 */
public interface SnapshotService {

    /**
     * Initializes a consumer by processing its associated remote snapshot.
     *
     * @param consumer The remote consumer containing the snapshot link and offset information.
     */
    void initialize(RemoteConsumer consumer);
}
