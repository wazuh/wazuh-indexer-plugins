/*
 * Copyright (C) 2024, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Represents a specific Product within a CTI Plan. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Product {
    private String identifier;
    private String type;
    private String name;
    private String description;
    private String resource;

    /** Default no-argument constructor. */
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
        return "Product{"
                + "identifier='"
                + this.identifier
                + '\''
                + ", type='"
                + this.type
                + '\''
                + ", name='"
                + this.name
                + '\''
                + ", description='"
                + this.description
                + '\''
                + ", resource='"
                + this.resource
                + '\''
                + '}';
    }
}
