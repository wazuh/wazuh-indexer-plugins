package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 * Represents a CTI plan.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Plan {
    private String name;
    private String description;
    private List<Product> products;

    /**
     * Default no-argument constructor.
     */
    public Plan() {}

    /**
     * Retrieves the name of the plan.
     *
     * @return the name of the plan.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Retrieves the description of the plan.
     *
     * @return the plan description.
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Retrieves the list of products associated with this plan.
     *
     * @return a {@link List} of {@link Product} objects, or {@code null} if none are set.
     */
    public List<Product> getProducts() {
        return this.products;
    }

    /**
     * Returns a string representation of the Plan object.
     *
     * @return a string containing the name, description, and the string representation of the associated products.
     */
    @Override
    public String toString() {
        return "Plan{" +
            "name='" + this.name + '\'' +
            ", description='" + this.description + '\'' +
            ", products=" + this.products +
            '}';
    }
}
