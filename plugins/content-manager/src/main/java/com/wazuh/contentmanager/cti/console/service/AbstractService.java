package com.wazuh.contentmanager.cti.console.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.contentmanager.cti.console.client.ApiClient;

/**
 * Abstract service class, for generalization.
 */
public abstract class AbstractService {

    final ApiClient client;
    final ObjectMapper mapper;

    /**
     * Default constructor
     */
    public AbstractService() {
        this.client = new ApiClient();
        this.mapper = new ObjectMapper();
    }
}
