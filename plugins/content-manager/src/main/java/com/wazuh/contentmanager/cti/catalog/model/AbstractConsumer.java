package com.wazuh.contentmanager.cti.catalog.model;

/**
 * Base class for Consumer models.
 * Contains shared properties between local and remote consumers.
 */
public abstract class AbstractConsumer {
    String name;
    String context;

    /**
     * Default constructor
     */
    public AbstractConsumer() {}

    /**
     * Gets the context identifier.
     *
     * @return The context string.
     */
    public String getContext() {
        return this.context;
    }

    /**
     * Gets the consumer name.
     *
     * @return The name string.
     */
    public String getName() {
        return this.name;
    }
}
