package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;

/**
 * Abstract service class, for generalization.
 */
public abstract class AbstractService {

    ApiClient client;
    final ObjectMapper mapper;

    /**
     * Default constructor
     */
    public AbstractService() {
        this.client = new ApiClient();
        this.mapper = new ObjectMapper();
    }

    /**
     * Use for testing only.
     * @param c mocked client.
     */
    public void setClient(ApiClient c) {
        this.close();
        this.client = c;
    }

    /**
     * Closes the underlying HTTP client. Should be called when the service is no longer needed.
     */
    public void close() {
        if (this.client != null) {
            this.client.close();
        }
    }
}
