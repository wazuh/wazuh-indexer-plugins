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
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;

/** Represents a CTI catalog plan. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Plan {
    private String name;

    @JsonProperty("is_public")
    private boolean isPublic;

    private List<Feature> features;

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
     * Returns whether this plan is publicly accessible without environment registration or
     * authentication.
     *
     * @return {@code true} if the plan is public, {@code false} otherwise.
     */
    public boolean isPublic() {
        return this.isPublic;
    }

    /**
     * Retrieves the list of features associated with this plan.
     *
     * @return a {@link List} of {@link Feature} objects, or {@code null} if none are set.
     */
    public List<Feature> getFeatures() {
        return this.features;
    }

    /**
     * Finds a feature by its type.
     *
     * @param type the feature type string to search for (e.g., {@code
     *     "cti:catalog:consumer:vulnerabilities"}).
     * @return the matching {@link Feature}, or {@code null} if no feature with the given type is
     *     found.
     */
    public Feature getFeature(String type) {
        if (this.features == null || type == null) {
            return null;
        }
        return this.features.stream().filter(f -> type.equals(f.getType())).findFirst().orElse(null);
    }

    /**
     * Returns a string representation of the Plan object.
     *
     * @return a string containing the name, isPublic flag, and the string representation of the
     *     associated features.
     */
    @Override
    public String toString() {
        return "Plan{"
                + "name='"
                + this.name
                + '\''
                + ", isPublic="
                + this.isPublic
                + ", features="
                + this.features
                + '}';
    }
}
