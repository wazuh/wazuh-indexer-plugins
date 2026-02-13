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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonObject;
import com.google.gson.ToNumberPolicy;

import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Model representing an IoC (Indicator of Compromise) resource. Unlike general resources, IoC
 * payloads have a flat structure where {@code id} and {@code enrichments} are at the root level,
 * without a {@code document} wrapper.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Ioc extends Resource {
    private static final Gson GSON =
            new GsonBuilder().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();

    @JsonProperty(Constants.KEY_ID)
    private String id;

    @JsonProperty(Constants.KEY_ENRICHMENTS)
    private List<Map<String, Object>> enrichments;

    /** Default constructor. */
    public Ioc() {}

    /**
     * Factory method to create an Ioc instance from a raw Gson JsonObject.
     *
     * @param payload The raw JSON object containing the IoC data.
     * @return A fully populated Ioc instance.
     */
    public static Ioc fromPayload(JsonObject payload) {
        Ioc ioc = new Ioc();

        // Populate common Resource fields (space, etc.)
        Resource resource = new Resource();
        resource.populateResource(ioc, payload);

        // Populate IoC-specific fields
        if (payload.has(Constants.KEY_ID)) {
            ioc.setId(payload.get(Constants.KEY_ID).getAsString());
        }
        if (payload.has(Constants.KEY_ENRICHMENTS)
                && payload.get(Constants.KEY_ENRICHMENTS).isJsonArray()) {
            ioc.setEnrichments(
                    GSON.fromJson(payload.getAsJsonArray(Constants.KEY_ENRICHMENTS), List.class));
        }

        return ioc;
    }

    /**
     * Gets the IoC identifier.
     *
     * @return The IoC id.
     */
    public String getId() {
        return this.id;
    }

    /**
     * Sets the IoC identifier.
     *
     * @param id The IoC id.
     */
    public void setId(String id) {
        this.id = id;
    }

    /**
     * Gets the enrichments list.
     *
     * @return A list of enrichment maps, each containing {@code custom}, {@code indicator}, and
     *     {@code source} data.
     */
    public List<Map<String, Object>> getEnrichments() {
        return this.enrichments;
    }

    /**
     * Sets the enrichments list.
     *
     * @param enrichments A list of enrichment maps.
     */
    public void setEnrichments(List<Map<String, Object>> enrichments) {
        this.enrichments = enrichments;
    }

    @Override
    public String toString() {
        return "Ioc{" + "id='" + this.id + '\'' + ", enrichments=" + this.enrichments + '}';
    }
}
