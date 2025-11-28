package com.wazuh.contentmanager.cti.catalog;

import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerService;

public class CtiCatalog {

    private ConsumerService consumerService;

    public CtiCatalog(ConsumerService consumerService) {
        this.consumerService = consumerService;
    }

}
