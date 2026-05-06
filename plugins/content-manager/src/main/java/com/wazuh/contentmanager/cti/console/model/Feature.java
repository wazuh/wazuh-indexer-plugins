/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

/**
 * Represents a feature within a CTI catalog plan. Each feature describes a specific content stream
 * (e.g., vulnerability data, IOC intelligence) available through the CTI API.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Feature {
    private String name;
    private String description;
    private String resource;
    private String type;

    /** Default no-argument constructor. */
    public Feature() {}

    /**
     * Retrieves the display name of the feature.
     *
     * @return the feature name.
     */
    public String getName() {
        return this.name;
    }

    /**
     * Retrieves the description of the feature.
     *
     * @return the feature description.
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Retrieves the resource URL for this feature. This URL points to the CTI catalog endpoint that
     * serves the feature's content.
     *
     * @return a string representing the resource URI.
     */
    public String getResource() {
        return this.resource;
    }

    /**
     * Retrieves the type of the feature. Known types include {@code
     * cti:catalog:consumer:vulnerabilities} and {@code cti:catalog:consumer:iocs}.
     *
     * @return the feature type string.
     */
    public String getType() {
        return this.type;
    }

    /**
     * Returns a string representation of the Feature.
     *
     * @return a string containing the name, description, resource, and type.
     */
    @Override
    public String toString() {
        return "Feature{"
                + "name='"
                + this.name
                + '\''
                + ", description='"
                + this.description
                + '\''
                + ", resource='"
                + this.resource
                + '\''
                + ", type='"
                + this.type
                + '\''
                + '}';
    }
}
