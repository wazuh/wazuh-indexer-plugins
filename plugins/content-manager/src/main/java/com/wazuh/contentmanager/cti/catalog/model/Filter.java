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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;

import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.YamlUtils;

/** Model representing a Filter resource with an additional YAML representation. */
public class Filter extends Resource {

    @JsonProperty("yaml")
    private String yaml;

    /** Default constructor. */
    public Filter() {
        super();
    }

    /**
     * Factory method to create a Filter instance from a raw JSON payload.
     *
     * @param payload The raw JSON object containing the filter data.
     * @return A populated Filter object with the generated YAML string.
     */
    public static Filter fromPayload(JsonNode payload) {
        Filter filter = new Filter();
        new Resource().populateResource(filter, payload);

        if (payload.has(Constants.KEY_DOCUMENT)) {
            filter.setYaml(YamlUtils.toYaml(payload.get(Constants.KEY_DOCUMENT)));
        }

        return filter;
    }

    /**
     * Gets the YAML string representation of this filter.
     *
     * @return The filter content in YAML format.
     */
    public String getYaml() {
        return this.yaml;
    }

    /**
     * Sets the YAML string representation of this filter.
     *
     * @param yaml The filter content in YAML format.
     */
    public void setYaml(String yaml) {
        this.yaml = yaml;
    }

    @Override
    public String toString() {
        return "Filter{" + "yaml='" + this.yaml + '\'' + ", " + super.toString() + '}';
    }
}
