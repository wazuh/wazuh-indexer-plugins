package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/**
 *  CTI plan DTO.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Plan {
    private String name;
    private String description;
    private List<Product> products;

    /**
     * Default constructor.
     */
    public Plan() {}

    public String getName() {
        return this.name;
    }

    public String getDescription() {
        return this.description;
    }

    public List<Product> getProducts() {
        return this.products;
    }


    @Override
    public String toString() {
        return "Plan{" +
            "name='" + this.name + '\'' +
            ", description='" + this.description + '\'' +
            ", products=" + this.products +
            '}';
    }
}
