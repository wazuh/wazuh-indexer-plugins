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

/**
 * Model representing an IoC (Indicator of Compromise) resource. Unlike general resources, IoC
 * payloads have a flat structure where {@code id} and {@code enrichments} are at the root level,
 * without a {@code document} wrapper.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Ioc extends Resource {
    private static final String ID_KEY = "id";
    private static final String ENRICHMENTS_KEY = "enrichments";
    private static final Gson GSON =
            new GsonBuilder().setObjectToNumberStrategy(ToNumberPolicy.LONG_OR_DOUBLE).create();

    @JsonProperty(ID_KEY)
    private String id;

    @JsonProperty(ENRICHMENTS_KEY)
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
        Resource.populateResource(ioc, payload);

        // Populate IoC-specific fields
        if (payload.has(ID_KEY)) {
            ioc.setId(payload.get(ID_KEY).getAsString());
        }
        if (payload.has(ENRICHMENTS_KEY) && payload.get(ENRICHMENTS_KEY).isJsonArray()) {
            ioc.setEnrichments(GSON.fromJson(payload.getAsJsonArray(ENRICHMENTS_KEY), List.class));
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
