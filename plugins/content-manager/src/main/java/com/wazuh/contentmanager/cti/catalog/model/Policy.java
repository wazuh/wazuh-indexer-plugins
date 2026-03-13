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

import org.opensearch.jobscheduler.repackage.com.cronutils.utils.VisibleForTesting;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

/**
 * Model representing a Policy resource within the Engine context.
 *
 * <p>A Policy defines the configuration and metadata for content processing, including the root
 * decoder, associated integrations, linked filters, and active enrichment categories. Policies
 * exist within different spaces (draft, test, custom, standard) and their resources can be promoted
 * between spaces.
 *
 * <p>The policy acts as a container that references integrations by their IDs and specifies the
 * root decoder to be used for content processing. It also controls Engine synchronization behavior
 * through the {@code enabled}, {@code index_unclassified_events}, and {@code
 * index_discarded_events} flags.
 *
 * <p>Field modification rules enforced by the PUT endpoint:
 *
 * <ul>
 *   <li>{@code id} and {@code date} are immutable after creation.
 *   <li>{@code integrations} and {@code filters} may be reordered but not added to or removed from
 *       via this endpoint.
 *   <li>{@code enrichments} may be freely added, removed, or reordered within the set of allowed
 *       values.
 *   <li>{@code enabled}, {@code index_unclassified_events}, and {@code index_discarded_events} are
 *       optional boolean flags; omitting them from the request preserves backward compatibility.
 * </ul>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Policy {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    // JSON Key Constants
    private static final String METADATA_KEY = "metadata";
    private static final String ROOT_DECODER_KEY = "root_decoder";
    private static final String INTEGRATIONS_KEY = "integrations";
    private static final String FILTERS_KEY = "filters";
    private static final String ENRICHMENTS_KEY = "enrichments";
    private static final String ID_KEY = "id";
    private static final String ENABLED_KEY = "enabled";
    private static final String INDEX_UNCLASSIFIED_EVENTS_KEY = "index_unclassified_events";
    private static final String INDEX_DISCARDED_EVENTS_KEY = "index_discarded_events";

    @JsonProperty(METADATA_KEY)
    private ResourceMetadata metadata;

    @JsonProperty(ROOT_DECODER_KEY)
    private String rootDecoder;

    @JsonProperty(INTEGRATIONS_KEY)
    private List<String> integrations;

    @JsonProperty(FILTERS_KEY)
    private List<String> filters;

    @JsonProperty(ENRICHMENTS_KEY)
    private List<String> enrichments;

    @JsonProperty(ID_KEY)
    private String id;

    @JsonProperty(ENABLED_KEY)
    private Boolean enabled;

    @JsonProperty(INDEX_UNCLASSIFIED_EVENTS_KEY)
    private Boolean indexUnclassifiedEvents;

    @JsonProperty(INDEX_DISCARDED_EVENTS_KEY)
    private Boolean indexDiscardedEvents;

    /** Default constructor. */
    public Policy() {
        this.metadata = new ResourceMetadata();
        this.metadata.setCompatibility(new ArrayList<>());
        this.metadata.setReferences(new ArrayList<>());
        this.integrations = new ArrayList<>();
        this.filters = new ArrayList<>();
        this.enrichments = new ArrayList<>();
    }

    /**
     * Constructs a new Policy with the specified parameters.
     *
     * @param id Unique identifier of the policy document.
     * @param metadata The metadata block for this policy.
     * @param rootDecoder The root decoder identifier.
     * @param integrations List of integration IDs referenced by this policy.
     * @param filters List of filter UUIDs linked to this policy.
     * @param enrichments List of active enrichment category names.
     * @param enabled Whether the policy is active and synchronized by the Engine; {@code null} if not
     *     set.
     * @param indexUnclassifiedEvents Whether uncategorized events are indexed into {@code
     *     wazuh-events-v5-unclassified}; {@code null} if not set.
     * @param indexDiscardedEvents Whether discarded events are indexed; {@code null} if not set.
     */
    @JsonCreator
    public Policy(
            @JsonProperty(ID_KEY) String id,
            @JsonProperty(METADATA_KEY) ResourceMetadata metadata,
            @JsonProperty(ROOT_DECODER_KEY) String rootDecoder,
            @JsonProperty(INTEGRATIONS_KEY) List<String> integrations,
            @JsonProperty(FILTERS_KEY) List<String> filters,
            @JsonProperty(ENRICHMENTS_KEY) List<String> enrichments,
            @JsonProperty(ENABLED_KEY) Boolean enabled,
            @JsonProperty(INDEX_UNCLASSIFIED_EVENTS_KEY) Boolean indexUnclassifiedEvents,
            @JsonProperty(INDEX_DISCARDED_EVENTS_KEY) Boolean indexDiscardedEvents) {
        this.id = id;
        this.metadata = metadata != null ? metadata : new ResourceMetadata();
        if (this.metadata.getCompatibility() == null) {
            this.metadata.setCompatibility(new ArrayList<>());
        }
        if (this.metadata.getReferences() == null) {
            this.metadata.setReferences(new ArrayList<>());
        }
        this.rootDecoder = rootDecoder;
        this.integrations = integrations != null ? integrations : new ArrayList<>();
        this.filters = filters != null ? filters : new ArrayList<>();
        this.enrichments = enrichments != null ? enrichments : new ArrayList<>();
        this.enabled = enabled;
        this.indexUnclassifiedEvents = indexUnclassifiedEvents;
        this.indexDiscardedEvents = indexDiscardedEvents;
    }

    /**
     * Factory method to create a Policy instance from a raw JsonNode.
     *
     * @param payload The raw JSON object containing the policy data.
     * @return A fully populated Policy instance.
     */
    public static Policy fromPayload(JsonNode payload) {
        Policy policy = MAPPER.convertValue(payload, Policy.class);
        // Filter null entries from list fields (Jackson preserves JSON nulls in arrays)
        if (policy.integrations != null) {
            policy.integrations.removeIf(java.util.Objects::isNull);
        }
        if (policy.filters != null) {
            policy.filters.removeIf(java.util.Objects::isNull);
        }
        if (policy.enrichments != null) {
            policy.enrichments.removeIf(java.util.Objects::isNull);
        }
        return policy;
    }

    /**
     * Converts the policy to a Map using Jackson.
     *
     * @return Map representation of the policy.
     */
    @VisibleForTesting
    public Map<String, Object> toMap() {
        return MAPPER.convertValue(this, Map.class);
    }

    /**
     * Converts the policy to an ObjectNode using Jackson.
     *
     * @return ObjectNode representation of the policy.
     */
    @VisibleForTesting
    public ObjectNode toJson() {
        return MAPPER.valueToTree(this);
    }

    /**
     * Adds an integration ID to the policy if it's not already present.
     *
     * @param integrationId The integration ID to add.
     */
    @VisibleForTesting
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
    @VisibleForTesting
    public boolean removeIntegration(String integrationId) {
        return this.integrations.remove(integrationId);
    }

    // Getters and Setters

    /**
     * Gets the metadata block for this policy.
     *
     * @return The metadata object.
     */
    public ResourceMetadata getMetadata() {
        return this.metadata;
    }

    /**
     * Sets the metadata block for this policy.
     *
     * @param metadata The metadata object to set.
     */
    public void setMetadata(ResourceMetadata metadata) {
        this.metadata = metadata;
    }

    /**
     * Gets the creation date of this policy (delegated to metadata).
     *
     * @return The creation date as a string.
     */
    public String getDate() {
        return this.metadata != null ? this.metadata.getDate() : null;
    }

    /**
     * Sets the creation date of this policy (delegated to metadata).
     *
     * @param date The creation date to set.
     */
    public void setDate(String date) {
        if (this.metadata == null) this.metadata = new ResourceMetadata();
        this.metadata.setDate(date);
    }

    /**
     * Gets the last modified date of this policy (delegated to metadata).
     *
     * @return The last modified date as a string.
     */
    public String getModified() {
        return this.metadata != null ? this.metadata.getModified() : null;
    }

    /**
     * Sets the last modified date of this policy (delegated to metadata).
     *
     * @param modified The last modified date to set.
     */
    public void setModified(String modified) {
        if (this.metadata == null) this.metadata = new ResourceMetadata();
        this.metadata.setModified(modified);
    }

    /**
     * Gets the title of this policy (delegated to metadata).
     *
     * @return The policy title.
     */
    public String getTitle() {
        return this.metadata != null ? this.metadata.getTitle() : null;
    }

    /**
     * Sets the title of this policy (delegated to metadata).
     *
     * @param title The policy title to set.
     */
    public void setTitle(String title) {
        if (this.metadata == null) this.metadata = new ResourceMetadata();
        this.metadata.setTitle(title);
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
     * Gets the author of this policy (delegated to metadata).
     *
     * @return The author name.
     */
    public String getAuthor() {
        return this.metadata != null ? this.metadata.getAuthor() : null;
    }

    /**
     * Sets the author of this policy (delegated to metadata).
     *
     * @param author The author name to set. If null, defaults to empty string.
     */
    public void setAuthor(String author) {
        if (this.metadata == null) this.metadata = new ResourceMetadata();
        this.metadata.setAuthor(author != null ? author : "");
    }

    /**
     * Gets the description of this policy (delegated to metadata).
     *
     * @return The policy description.
     */
    public String getDescription() {
        return this.metadata != null ? this.metadata.getDescription() : null;
    }

    /**
     * Sets the description of this policy (delegated to metadata).
     *
     * @param description The policy description to set. If null, defaults to empty string.
     */
    public void setDescription(String description) {
        if (this.metadata == null) this.metadata = new ResourceMetadata();
        this.metadata.setDescription(description != null ? description : "");
    }

    /**
     * Gets the detailed documentation for this policy (delegated to metadata).
     *
     * @return The policy documentation.
     */
    public String getDocumentation() {
        return this.metadata != null ? this.metadata.getDocumentation() : null;
    }

    /**
     * Sets the detailed documentation for this policy (delegated to metadata).
     *
     * @param documentation The policy documentation to set. If null, defaults to empty string.
     */
    public void setDocumentation(String documentation) {
        if (this.metadata == null) this.metadata = new ResourceMetadata();
        this.metadata.setDocumentation(documentation != null ? documentation : "");
    }

    /**
     * Gets the external references or links related to this policy (delegated to metadata).
     *
     * @return The list of policy references.
     */
    public List<String> getReferences() {
        return this.metadata != null ? this.metadata.getReferences() : new ArrayList<>();
    }

    /**
     * Sets the external references or links related to this policy (delegated to metadata).
     *
     * @param references The list of policy references to set. If null, an empty list is used.
     */
    public void setReferences(List<String> references) {
        if (this.metadata == null) this.metadata = new ResourceMetadata();
        this.metadata.setReferences(references != null ? references : new ArrayList<>());
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

    /**
     * Gets whether this policy is active and synchronized by the Engine.
     *
     * @return The enabled flag, or null if not set.
     */
    public Boolean getEnabled() {
        return this.enabled;
    }

    /**
     * Sets whether this policy is active and synchronized by the Engine.
     *
     * @param enabled The enabled flag to set.
     */
    public void setEnabled(Boolean enabled) {
        this.enabled = enabled;
    }

    /**
     * Gets whether uncategorized events are indexed into wazuh-events-v5-unclassified.
     *
     * @return The index_unclassified_events flag, or null if not set.
     */
    public Boolean getIndexUnclassifiedEvents() {
        return this.indexUnclassifiedEvents;
    }

    /**
     * Sets whether uncategorized events are indexed into wazuh-events-v5-unclassified.
     *
     * @param indexUnclassifiedEvents The flag to set.
     */
    public void setIndexUnclassifiedEvents(Boolean indexUnclassifiedEvents) {
        this.indexUnclassifiedEvents = indexUnclassifiedEvents;
    }

    /**
     * Gets whether discarded events are indexed.
     *
     * @return The index_discarded_events flag, or null if not set.
     */
    public Boolean getIndexDiscardedEvents() {
        return this.indexDiscardedEvents;
    }

    /**
     * Sets whether discarded events are indexed.
     *
     * @param indexDiscardedEvents The flag to set.
     */
    public void setIndexDiscardedEvents(Boolean indexDiscardedEvents) {
        this.indexDiscardedEvents = indexDiscardedEvents;
    }

    @Override
    public String toString() {
        return "Policy{"
                + "metadata="
                + this.metadata
                + ", rootDecoder='"
                + this.rootDecoder
                + '\''
                + ", integrations="
                + this.integrations
                + ", filters="
                + this.filters
                + ", enrichments="
                + this.enrichments
                + ", id='"
                + this.id
                + '\''
                + ", enabled="
                + this.enabled
                + ", indexUnclassifiedEvents="
                + this.indexUnclassifiedEvents
                + ", indexDiscardedEvents="
                + this.indexDiscardedEvents
                + '}';
    }
}
