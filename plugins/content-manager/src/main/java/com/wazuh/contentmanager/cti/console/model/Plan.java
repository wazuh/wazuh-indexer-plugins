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

import java.util.List;

/** Represents a CTI plan. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Plan {
    private String name;
    private String description;
    private List<Product> products;

    /** Default no-argument constructor. */
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
     * @return a string containing the name, description, and the string representation of the
     *     associated products.
     */
    @Override
    public String toString() {
        return "Plan{"
                + "name='"
                + this.name
                + '\''
                + ", description='"
                + this.description
                + '\''
                + ", products="
                + this.products
                + '}';
    }
}
