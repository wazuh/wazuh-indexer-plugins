package com.wazuh.contentmanager.cti.catalog.service;

import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

/**
 * Service interface for managing and retrieving CTI Catalog consumer states.
 */
public interface ConsumerService {

    /**
     * Retrieves the current local consumer state.
     *
     * @return The {@link LocalConsumer} object representing the local state.
     */
    LocalConsumer getLocalConsumer();

    /**
     * Retrieves the current remote consumer state.
     *
     * @return The {@link RemoteConsumer} object representing the remote state.
     */
    RemoteConsumer getRemoteConsumer();
}
