package com.wazuh.contentmanager.cti.catalog.model;


public abstract class AbstractConsumer {
    String name;
    String context;

    /**
     * Default constructor
     */
    public AbstractConsumer() {}

    public String getContext() {
        return context;
    }

    public String getName() {
        return name;
    }
}
