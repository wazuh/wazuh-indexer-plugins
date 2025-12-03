package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/**
 * Represents a specific Product within a CTI Plan.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Product {
    private String identifier;
    private String type;
    private String name;
    private String description;
    private String resource;

    /**
     * Default no-argument constructor.
     */
    public Product() {}

    /**
     * Retrieves the unique identifier of the product.
     *
     * @return the product identifier string.
     */
    public String getIdentifier() {
        return this.identifier;
    }

    /**
     * Retrieves the type or category of the product.
     *
     * @return the product type.
     */
    public String getType() {
        return this.type;
    }

    /**
     * Retrieves the display name of the product.
     *
     * @return the product name.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Retrieves the description of the product.
     *
     * @return the product description.
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Retrieves the resource location for this product.
     *
     * @return a string representing the resource URI or path.
     */
    public String getResource() {
        return this.resource;
    }

    /**
     * Returns a string representation of the Product.
     *
     * @return a string containing the identifier, type, name, description, and resource.
     */
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
