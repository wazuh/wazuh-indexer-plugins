package com.wazuh.contentmanager.cti.catalog;

import com.wazuh.contentmanager.cti.catalog.service.ConsumerService;

/**
 * Represents the CTI Catalog.
 * Acts as a facade or entry point for catalog-related operations, primarily managing consumers.
 */
public class CtiCatalog {

    private ConsumerService consumerService;
    /**
     * Constructs a new CtiCatalog instance.
     *
     * @param consumerService The service used to manage local and remote consumers.
     */
    public CtiCatalog(ConsumerService consumerService) {
        this.consumerService = consumerService;
    }
}
