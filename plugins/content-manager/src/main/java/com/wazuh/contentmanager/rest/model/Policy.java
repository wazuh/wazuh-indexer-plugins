/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.rest.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Model representing a Policy resource within the Engine context.
 *
 * <p>A Policy defines the configuration and metadata for content processing, including the root
 * decoder and associated integrations. Policies exist within different spaces (draft, test, custom,
 * standard) and their resources can be promoted between spaces.
 *
 * <p>The policy acts as a container that references integrations by their IDs and specifies the
 * root decoder to be used for content processing.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Policy {
    // JSON Key Constants
    private static final String TYPE_KEY = "type";
    private static final String ROOT_DECODER_KEY = "root_decoder";
    private static final String INTEGRATIONS_KEY = "integrations";
    private static final String AUTHOR_KEY = "author";
    private static final String DESCRIPTION_KEY = "description";
    private static final String DOCUMENTATION_KEY = "documentation";
    private static final String REFERENCES_KEY = "references";

    @JsonProperty(TYPE_KEY)
    private String type;

    @JsonProperty(ROOT_DECODER_KEY)
    private String rootDecoder;

    @JsonProperty(INTEGRATIONS_KEY)
    private List<String> integrations;

    @JsonProperty(AUTHOR_KEY)
    private String author;

    @JsonProperty(DESCRIPTION_KEY)
    private String description;

    @JsonProperty(DOCUMENTATION_KEY)
    private String documentation;

    @JsonProperty(REFERENCES_KEY)
    private String references;

    /** Default constructor. */
    public Policy() {
        this.type = "policy";
        this.integrations = new ArrayList<>();
    }

    /**
     * Constructs a new Policy with the specified parameters.
     *
     * @param type The type of resource (should be "policy").
     * @param rootDecoder The root decoder identifier.
     * @param integrations List of integration IDs.
     * @param author The author of the policy.
     * @param description A brief description of the policy.
     * @param documentation Detailed documentation for the policy.
     * @param references External references or links related to the policy.
     */
    @JsonCreator
    public Policy(
            @JsonProperty(TYPE_KEY) String type,
            @JsonProperty(ROOT_DECODER_KEY) String rootDecoder,
            @JsonProperty(INTEGRATIONS_KEY) List<String> integrations,
            @JsonProperty(AUTHOR_KEY) String author,
            @JsonProperty(DESCRIPTION_KEY) String description,
            @JsonProperty(DOCUMENTATION_KEY) String documentation,
            @JsonProperty(REFERENCES_KEY) String references) {
        this.type = type != null ? type : "policy";
        this.rootDecoder = rootDecoder;
        this.integrations = integrations != null ? integrations : new ArrayList<>();
        this.author = author;
        this.description = description;
        this.documentation = documentation;
        this.references = references;
    }

    /**
     * Factory method to create a Policy instance from a raw Gson JsonObject.
     *
     * @param payload The raw JSON object containing the policy data.
     * @return A fully populated Policy instance.
     */
    public static Policy fromPayload(JsonObject payload) {
        Policy policy = new Policy();

        if (payload.has(TYPE_KEY)) {
            policy.setType(payload.get(TYPE_KEY).getAsString());
        }

        if (payload.has(ROOT_DECODER_KEY) && !payload.get(ROOT_DECODER_KEY).isJsonNull()) {
            policy.setRootDecoder(payload.get(ROOT_DECODER_KEY).getAsString());
        }

        if (payload.has(INTEGRATIONS_KEY) && payload.get(INTEGRATIONS_KEY).isJsonArray()) {
            JsonArray integrationsArray = payload.getAsJsonArray(INTEGRATIONS_KEY);
            List<String> integrationsList = new ArrayList<>();
            for (JsonElement element : integrationsArray) {
                if (!element.isJsonNull()) {
                    integrationsList.add(element.getAsString());
                }
            }
            policy.setIntegrations(integrationsList);
        }

        if (payload.has(AUTHOR_KEY) && !payload.get(AUTHOR_KEY).isJsonNull()) {
            policy.setAuthor(payload.get(AUTHOR_KEY).getAsString());
        }

        if (payload.has(DESCRIPTION_KEY) && !payload.get(DESCRIPTION_KEY).isJsonNull()) {
            policy.setDescription(payload.get(DESCRIPTION_KEY).getAsString());
        }

        if (payload.has(DOCUMENTATION_KEY) && !payload.get(DOCUMENTATION_KEY).isJsonNull()) {
            policy.setDocumentation(payload.get(DOCUMENTATION_KEY).getAsString());
        }

        if (payload.has(REFERENCES_KEY) && !payload.get(REFERENCES_KEY).isJsonNull()) {
            policy.setReferences(payload.get(REFERENCES_KEY).getAsString());
        }

        return policy;
    }

    /**
     * Converts this Policy to a Map representation suitable for indexing.
     *
     * @return A Map containing all policy fields.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> map = new HashMap<>();

        if (this.type != null) {
            map.put(TYPE_KEY, this.type);
        }
        if (this.rootDecoder != null) {
            map.put(ROOT_DECODER_KEY, this.rootDecoder);
        }
        if (this.integrations != null && !this.integrations.isEmpty()) {
            map.put(INTEGRATIONS_KEY, this.integrations);
        }
        if (this.author != null) {
            map.put(AUTHOR_KEY, this.author);
        }
        if (this.description != null) {
            map.put(DESCRIPTION_KEY, this.description);
        }
        if (this.documentation != null) {
            map.put(DOCUMENTATION_KEY, this.documentation);
        }
        if (this.references != null) {
            map.put(REFERENCES_KEY, this.references);
        }

        return map;
    }

    /**
     * Converts this Policy to a Gson JsonObject representation.
     *
     * @return A JsonObject containing all policy fields.
     */
    public JsonObject toJson() {
        JsonObject jsonObject = new JsonObject();

        if (this.type != null) {
            jsonObject.addProperty(TYPE_KEY, this.type);
        }
        if (this.rootDecoder != null) {
            jsonObject.addProperty(ROOT_DECODER_KEY, this.rootDecoder);
        }
        if (this.integrations != null) {
            JsonArray integrationsArray = new JsonArray();
            for (String integration : this.integrations) {
                integrationsArray.add(integration);
            }
            jsonObject.add(INTEGRATIONS_KEY, integrationsArray);
        }
        if (this.author != null) {
            jsonObject.addProperty(AUTHOR_KEY, this.author);
        }
        if (this.description != null) {
            jsonObject.addProperty(DESCRIPTION_KEY, this.description);
        }
        if (this.documentation != null) {
            jsonObject.addProperty(DOCUMENTATION_KEY, this.documentation);
        }
        if (this.references != null) {
            jsonObject.addProperty(REFERENCES_KEY, this.references);
        }

        return jsonObject;
    }

    /**
     * Adds an integration ID to the policy's integrations list.
     *
     * @param integrationId The integration ID to add.
     */
    public void addIntegration(String integrationId) {
        if (integrationId != null && !this.integrations.contains(integrationId)) {
            this.integrations.add(integrationId);
        }
    }

    /**
     * Removes an integration ID from the policy's integrations list.
     *
     * @param integrationId The integration ID to remove.
     * @return true if the integration was removed, false otherwise.
     */
    public boolean removeIntegration(String integrationId) {
        return this.integrations.remove(integrationId);
    }

    // Getters and Setters

    /**
     * Gets the type of this resource.
     *
     * @return The resource type (should be "policy").
     */
    public String getType() {
        return this.type;
    }

    /**
     * Sets the type of this resource.
     *
     * @param type The resource type to set.
     */
    public void setType(String type) {
        this.type = type;
    }

    /**
     * Gets the root decoder identifier.
     *
     * @return The root decoder identifier.
     */
    public String getRootDecoder() {
        return this.rootDecoder;
    }

    /**
     * Sets the root decoder identifier.
     *
     * @param rootDecoder The root decoder identifier to set.
     */
    public void setRootDecoder(String rootDecoder) {
        this.rootDecoder = rootDecoder;
    }

    /**
     * Gets the list of integration IDs associated with this policy.
     *
     * @return The list of integration IDs.
     */
    public List<String> getIntegrations() {
        return this.integrations;
    }

    /**
     * Sets the list of integration IDs for this policy.
     *
     * @param integrations The list of integration IDs to set. If null, an empty list is used.
     */
    public void setIntegrations(List<String> integrations) {
        this.integrations = integrations != null ? integrations : new ArrayList<>();
    }

    /**
     * Gets the author of this policy.
     *
     * @return The author name.
     */
    public String getAuthor() {
        return this.author;
    }

    /**
     * Sets the author of this policy.
     *
     * @param author The author name to set.
     */
    public void setAuthor(String author) {
        this.author = author;
    }

    /**
     * Gets the description of this policy.
     *
     * @return The policy description.
     */
    public String getDescription() {
        return this.description;
    }

    /**
     * Sets the description of this policy.
     *
     * @param description The policy description to set.
     */
    public void setDescription(String description) {
        this.description = description;
    }

    /**
     * Gets the detailed documentation for this policy.
     *
     * @return The policy documentation.
     */
    public String getDocumentation() {
        return this.documentation;
    }

    /**
     * Sets the detailed documentation for this policy.
     *
     * @param documentation The policy documentation to set.
     */
    public void setDocumentation(String documentation) {
        this.documentation = documentation;
    }

    /**
     * Gets the external references or links related to this policy.
     *
     * @return The policy references.
     */
    public String getReferences() {
        return this.references;
    }

    /**
     * Sets the external references or links related to this policy.
     *
     * @param references The policy references to set.
     */
    public void setReferences(String references) {
        this.references = references;
    }

    @Override
    public String toString() {
        return "Policy{"
                + "type='"
                + this.type
                + '\''
                + ", rootDecoder='"
                + this.rootDecoder
                + '\''
                + ", integrations="
                + this.integrations
                + ", author='"
                + this.author
                + '\''
                + ", description='"
                + this.description
                + '\''
                + ", documentation='"
                + this.documentation
                + '\''
                + ", references='"
                + this.references
                + '\''
                + '}';
    }
}
