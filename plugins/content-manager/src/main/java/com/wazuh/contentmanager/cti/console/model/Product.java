package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * CTI product DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Product {
    private String identifier;
    private String type;
    private String name;
    private String description;
    private String resource;

    /**
     * Default constructor.
     */
    public Product() {}

    public String getIdentifier() {
        return this.identifier;
    }

    public String getType() {
        return this.type;
    }

    public String getName() {
        return this.name;
    }

    public String getDescription() {
        return this.description;
    }

    public String getResource() {
        return this.resource;
    }

    @Override
    public String toString() {
        return "Product{" +
            "identifier='" + this.identifier + '\'' +
            ", type='" + this.type + '\'' +
            ", name='" + this.name + '\'' +
            ", description='" + this.description + '\'' +
            ", resource='" + this.resource + '\'' +
            '}';
    }
}
