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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
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
@JsonInclude(JsonInclude.Include.NON_EMPTY)
public class Policy {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // JSON Key Constants
    private static final String TITLE_KEY = "title";
    private static final String DATE_KEY = "date";
    private static final String MODIFIED_KEY = "modified";
    private static final String ROOT_DECODER_KEY = "root_decoder";
    private static final String INTEGRATIONS_KEY = "integrations";
    private static final String FILTERS_KEY = "filters";
    private static final String ENRICHMENTS_KEY = "enrichments";
    private static final String AUTHOR_KEY = "author";
    private static final String DESCRIPTION_KEY = "description";
    private static final String DOCUMENTATION_KEY = "documentation";
    private static final String REFERENCES_KEY = "references";
    private static final String ID_KEY = "id";

    @JsonProperty(TITLE_KEY)
    private String title;

    @JsonProperty(DATE_KEY)
    private String date;

    @JsonProperty(MODIFIED_KEY)
    private String modified;

    @JsonProperty(ROOT_DECODER_KEY)
    private String rootDecoder;

    @JsonProperty(INTEGRATIONS_KEY)
    private List<String> integrations;

    @JsonProperty(FILTERS_KEY)
    private List<String> filters;

    @JsonProperty(ENRICHMENTS_KEY)
    private List<String> enrichments;

    @JsonProperty(AUTHOR_KEY)
    private String author;

    @JsonProperty(DESCRIPTION_KEY)
    private String description;

    @JsonProperty(DOCUMENTATION_KEY)
    private String documentation;

    @JsonProperty(REFERENCES_KEY)
    private List<String> references;

    @JsonProperty(ID_KEY)
    private String id;

    /** Default constructor. */
    public Policy() {
        this.integrations = new ArrayList<>();
        this.filters = new ArrayList<>();
        this.enrichments = new ArrayList<>();
        this.references = new ArrayList<>();
        this.date = null;
        this.modified = null;
    }

    /**
     * Constructs a new Policy with the specified parameters.
     *
     * @param rootDecoder The root decoder identifier.
     * @param integrations List of integration IDs.
     * @param filters List of filter IDs.
     * @param enrichments List of enrichment types.
     * @param author The author of the policy.
     * @param description A brief description of the policy.
     * @param documentation Detailed documentation for the policy.
     * @param references External references or links related to the policy.
     */
    @JsonCreator
    public Policy(
            @JsonProperty(ID_KEY) String id,
            @JsonProperty(TITLE_KEY) String title,
            @JsonProperty(DATE_KEY) String date,
            @JsonProperty(MODIFIED_KEY) String modified,
            @JsonProperty(ROOT_DECODER_KEY) String rootDecoder,
            @JsonProperty(INTEGRATIONS_KEY) List<String> integrations,
            @JsonProperty(FILTERS_KEY) List<String> filters,
            @JsonProperty(ENRICHMENTS_KEY) List<String> enrichments,
            @JsonProperty(AUTHOR_KEY) String author,
            @JsonProperty(DESCRIPTION_KEY) String description,
            @JsonProperty(DOCUMENTATION_KEY) String documentation,
            @JsonProperty(REFERENCES_KEY) List<String> references) {
        this.id = id;
        this.title = title;
        this.date = date;
        this.modified = modified;
        this.rootDecoder = rootDecoder;
        this.integrations = integrations != null ? integrations : new ArrayList<>();
        this.filters = filters != null ? filters : new ArrayList<>();
        this.enrichments = enrichments != null ? enrichments : new ArrayList<>();
        this.author = author;
        this.description = description;
        this.documentation = documentation;
        this.references = references != null ? references : new ArrayList<>();
    }

    /**
     * Factory method to create a Policy instance from a raw JsonNode.
     *
     * @param payload The raw JSON object containing the policy data.
     * @return A fully populated Policy instance.
     */
    public static Policy fromPayload(JsonNode payload) {
        Policy policy = new Policy();
        if (payload.has(ID_KEY) && !payload.get(ID_KEY).isNull()) {
            policy.setId(payload.get(ID_KEY).asText());
        }

        if (payload.has(DATE_KEY) && !payload.get(DATE_KEY).isNull()) {
            policy.setDate(payload.get(DATE_KEY).asText());
        }

        if (payload.has(MODIFIED_KEY) && !payload.get(MODIFIED_KEY).isNull()) {
            policy.setModified(payload.get(MODIFIED_KEY).asText());
        }

        if (payload.has(TITLE_KEY) && !payload.get(TITLE_KEY).isNull()) {
            policy.title = payload.get(TITLE_KEY).asText();
        }

        if (payload.has(ROOT_DECODER_KEY) && !payload.get(ROOT_DECODER_KEY).isNull()) {
            policy.setRootDecoder(payload.get(ROOT_DECODER_KEY).asText());
        }

        if (payload.has(INTEGRATIONS_KEY) && payload.get(INTEGRATIONS_KEY).isArray()) {
            List<String> integrationsList = new ArrayList<>();
            payload
                    .get(INTEGRATIONS_KEY)
                    .forEach(
                            n -> {
                                if (!n.isNull()) integrationsList.add(n.asText());
                            });
            policy.setIntegrations(integrationsList);
        }

        if (payload.has(FILTERS_KEY) && payload.get(FILTERS_KEY).isArray()) {
            List<String> filtersList = new ArrayList<>();
            payload
                    .get(FILTERS_KEY)
                    .forEach(
                            n -> {
                                if (!n.isNull()) filtersList.add(n.asText());
                            });
            policy.setFilters(filtersList);
        }

        if (payload.has(ENRICHMENTS_KEY) && payload.get(ENRICHMENTS_KEY).isArray()) {
            List<String> enrichmentsList = new ArrayList<>();
            payload
                    .get(ENRICHMENTS_KEY)
                    .forEach(
                            n -> {
                                if (!n.isNull()) enrichmentsList.add(n.asText());
                            });
            policy.setEnrichments(enrichmentsList);
        }

        if (payload.has(AUTHOR_KEY) && !payload.get(AUTHOR_KEY).isNull()) {
            policy.setAuthor(payload.get(AUTHOR_KEY).asText());
        }

        if (payload.has(DESCRIPTION_KEY) && !payload.get(DESCRIPTION_KEY).isNull()) {
            policy.setDescription(payload.get(DESCRIPTION_KEY).asText());
        }

        if (payload.has(DOCUMENTATION_KEY) && !payload.get(DOCUMENTATION_KEY).isNull()) {
            policy.setDocumentation(payload.get(DOCUMENTATION_KEY).asText());
        }

        if (payload.has(REFERENCES_KEY) && payload.get(REFERENCES_KEY).isArray()) {
            List<String> referencesList = new ArrayList<>();
            payload
                    .get(REFERENCES_KEY)
                    .forEach(
                            n -> {
                                if (!n.isNull()) referencesList.add(n.asText());
                            });
            policy.setReferences(referencesList);
        }

        return policy;
    }

    /**
     * Converts the policy to a Map using Jackson.
     *
     * @return Map representation of the policy.
     */
    // TODO: This method is only used in the tests and can probably be deleted
    public Map<String, Object> toMap() {
        return MAPPER.convertValue(this, Map.class);
    }

    /**
     * Converts the policy to an ObjectNode using Jackson.
     *
     * @return ObjectNode representation of the policy.
     */
    // TODO: This method is only used in the tests and can probably be deleted
    public ObjectNode toJson() {
        return MAPPER.valueToTree(this);
    }

    /**
     * Adds an integration ID to the policy if it's not already present.
     *
     * @param integrationId The integration ID to add.
     */
    // TODO: This method is only used in the tests and can probably be deleted
    public void addIntegration(String integrationId) {
        if (integrationId != null && !this.integrations.contains(integrationId)) {
            this.integrations.add(integrationId);
        }
    }

    /**
     * Removes an integration ID from the policy.
     *
     * @param integrationId The integration ID to remove.
     * @return true if the list contained the specified element.
     */
    // TODO: This method is only used in the tests and can probably be deleted
    public boolean removeIntegration(String integrationId) {
        return this.integrations.remove(integrationId);
    }

    // Getters and Setters
    /**
     * Gets the creation date of this policy.
     *
     * @return The creation date as a string.
     */
    public String getDate() {
        return this.date;
    }

    /**
     * Sets the creation date of this policy.
     *
     * @param date The creation date to set.
     */
    public void setDate(String date) {
        this.date = date;
    }

    /**
     * Gets the last modified date of this policy.
     *
     * @return The last modified date as a string.
     */
    public String getModified() {
        return this.modified;
    }

    /**
     * Sets the last modified date of this policy.
     *
     * @param modified The last modified date to set.
     */
    public void setModified(String modified) {
        this.modified = modified;
    }

    /**
     * Gets the title of this policy.
     *
     * @return The policy title.
     */
    public String getTitle() {
        return this.title;
    }

    /**
     * Sets the title of this policy.
     *
     * @param title The policy title to set.
     */
    public void setTitle(String title) {
        this.title = title;
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
     * @param rootDecoder The root decoder identifier to set. If null, defaults to empty string.
     */
    public void setRootDecoder(String rootDecoder) {
        this.rootDecoder = rootDecoder != null ? rootDecoder : "";
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
     * Gets the list of filter IDs associated with this policy.
     *
     * @return The list of filter IDs.
     */
    public List<String> getFilters() {
        return this.filters;
    }

    /**
     * Sets the list of filter IDs for this policy.
     *
     * @param filters The list of filter IDs to set. If null, an empty list is used.
     */
    public void setFilters(List<String> filters) {
        this.filters = filters != null ? filters : new ArrayList<>();
    }

    /**
     * Gets the list of enrichment types associated with this policy.
     *
     * @return The list of enrichment types.
     */
    public List<String> getEnrichments() {
        return this.enrichments;
    }

    /**
     * Sets the list of enrichment types for this policy.
     *
     * @param enrichments The list of enrichment types to set. If null, an empty list is used.
     */
    public void setEnrichments(List<String> enrichments) {
        this.enrichments = enrichments != null ? enrichments : new ArrayList<>();
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
     * @param author The author name to set. If null, defaults to empty string.
     */
    public void setAuthor(String author) {
        this.author = author != null ? author : "";
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
     * @param description The policy description to set. If null, defaults to empty string.
     */
    public void setDescription(String description) {
        this.description = description != null ? description : "";
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
     * @param documentation The policy documentation to set. If null, defaults to empty string.
     */
    public void setDocumentation(String documentation) {
        this.documentation = documentation != null ? documentation : "";
    }

    /**
     * Gets the external references or links related to this policy.
     *
     * @return The list of policy references.
     */
    public List<String> getReferences() {
        return this.references;
    }

    /**
     * Sets the external references or links related to this policy.
     *
     * @param references The list of policy references to set. If null, an empty list is used.
     */
    public void setReferences(List<String> references) {
        this.references = references != null ? references : new ArrayList<>();
    }

    /**
     * Gets the id related to this policy.
     *
     * @return The id of the policy document.
     */
    public String getId() {
        return this.id;
    }

    /**
     * Sets the id related to this policy.
     *
     * @param id The new id of the policy document.
     */
    public void setId(String id) {
        this.id = id;
    }

    @Override
    public String toString() {
        return "Policy{"
                + "title='"
                + this.title
                + '\''
                + ", date='"
                + this.date
                + '\''
                + ", modified='"
                + this.modified
                + '\''
                + ", rootDecoder='"
                + this.rootDecoder
                + '\''
                + ", integrations="
                + this.integrations
                + ", filters="
                + this.filters
                + ", enrichments="
                + this.enrichments
                + ", author='"
                + this.author
                + '\''
                + ", description='"
                + this.description
                + '\''
                + ", documentation='"
                + this.documentation
                + '\''
                + ", references="
                + this.references
                + ", id='"
                + this.id
                + '\''
                + '}';
    }
}
