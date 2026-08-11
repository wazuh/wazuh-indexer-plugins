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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.ArrayList;
import java.util.List;

import com.wazuh.contentmanager.utils.Constants;

/**
 * The user's overrides for one space, as held in the registry document.
 *
 * <p>The {@code standard} space is rebuilt from CTI, so anything a user writes there needs an
 * explicit mechanism to survive: the rebuild replaces the policy document wholesale, and deletes
 * the filters and the integrations outright. All three therefore live here.
 *
 * <p>Absence is meaningful throughout: a {@code null} setting means the user never decided that
 * field and CTI keeps deciding it. Enrichments are held as a delta rather than as a list so that
 * values CTI publishes later still reach a user who customised the selection.
 *
 * <p>This class is serialization only; all indexing lives in {@code UserOverridesService}.
 */
public final class UserOverrides {

    private final PolicySettings policy;
    private final List<StoredFilter> filters;
    private final List<IntegrationOverride> integrations;

    /**
     * There is deliberately no shorter constructor. Every section is passed explicitly so that adding
     * one forces each caller to decide what happens to the others, rather than dropping them
     * silently.
     *
     * @param policy the policy settings the user decided, or {@code null} if none.
     * @param filters the filters the user created; never {@code null} once constructed.
     * @param integrations the integration decisions the user made; never {@code null} once
     *     constructed.
     */
    public UserOverrides(
            PolicySettings policy, List<StoredFilter> filters, List<IntegrationOverride> integrations) {
        this.policy = policy;
        this.filters = filters != null ? filters : new ArrayList<>();
        this.integrations = integrations != null ? integrations : new ArrayList<>();
    }

    /**
     * @return the policy settings the user decided, or {@code null} if they never saved the policy.
     */
    public PolicySettings getPolicy() {
        return this.policy;
    }

    /**
     * @return the filters the user created in this space; empty if none.
     */
    public List<StoredFilter> getFilters() {
        return this.filters;
    }

    /**
     * @return the integration decisions the user made in this space; empty if none.
     */
    public List<IntegrationOverride> getIntegrations() {
        return this.integrations;
    }

    /**
     * Reads one space's overrides out of the registry.
     *
     * @param registryRoot the {@code user_overrides} node of the registry document, or {@code null}
     *     when the registry does not exist yet.
     * @param spaceName the space to read.
     * @return that space's overrides; empty when there are none.
     */
    public static UserOverrides forSpace(JsonNode registryRoot, String spaceName) {
        if (registryRoot == null || !registryRoot.has(spaceName)) {
            return new UserOverrides(null, new ArrayList<>(), new ArrayList<>());
        }
        JsonNode spaceNode = registryRoot.get(spaceName);

        PolicySettings settings = null;
        if (spaceNode.has(Constants.KEY_POLICY_SETTINGS)) {
            settings = PolicySettings.from(spaceNode.get(Constants.KEY_POLICY_SETTINGS));
        }

        List<StoredFilter> stored = new ArrayList<>();
        if (spaceNode.has(Constants.KEY_STORED_FILTERS)) {
            for (JsonNode entry : spaceNode.get(Constants.KEY_STORED_FILTERS)) {
                stored.add(
                        new StoredFilter(
                                entry.path(Constants.KEY_ID).asText(null),
                                entry.path(Constants.KEY_DOCUMENT).asText(null)));
            }
        }
        List<IntegrationOverride> overriddenIntegrations = new ArrayList<>();
        if (spaceNode.has(Constants.KEY_INTEGRATION_OVERRIDES)) {
            for (JsonNode entry : spaceNode.get(Constants.KEY_INTEGRATION_OVERRIDES)) {
                overriddenIntegrations.add(
                        new IntegrationOverride(
                                entry.path(Constants.KEY_ID).asText(null),
                                entry.path(Constants.KEY_ENABLED).asBoolean()));
            }
        }
        return new UserOverrides(settings, stored, overriddenIntegrations);
    }

    /**
     * Writes this instance into the registry under {@code spaceName}, replacing whatever was there.
     *
     * @param registryRoot the {@code user_overrides} node to write into.
     * @param spaceName the space to write.
     */
    public void writeInto(ObjectNode registryRoot, String spaceName) {
        ObjectNode spaceNode = registryRoot.objectNode();

        if (this.policy != null) {
            spaceNode.set(Constants.KEY_POLICY_SETTINGS, this.policy.toNode(registryRoot));
        }

        ArrayNode filtersNode = registryRoot.arrayNode();
        for (StoredFilter filter : this.filters) {
            ObjectNode entry = registryRoot.objectNode();
            entry.put(Constants.KEY_ID, filter.getId());
            entry.put(Constants.KEY_DOCUMENT, filter.getDocument());
            filtersNode.add(entry);
        }
        spaceNode.set(Constants.KEY_STORED_FILTERS, filtersNode);

        ArrayNode integrationsNode = registryRoot.arrayNode();
        for (IntegrationOverride integration : this.integrations) {
            ObjectNode entry = registryRoot.objectNode();
            entry.put(Constants.KEY_ID, integration.getId());
            entry.put(Constants.KEY_ENABLED, integration.getEnabled());
            integrationsNode.add(entry);
        }
        spaceNode.set(Constants.KEY_INTEGRATION_OVERRIDES, integrationsNode);

        registryRoot.set(spaceName, spaceNode);
    }

    /**
     * The four settings a user can change on the standard policy.
     *
     * <p>All four are recorded on every save, by design: editing the standard policy makes its
     * settings the user's from then on. A {@code null} field means the user never saved at all.
     */
    public static final class PolicySettings {

        private final Boolean enabled;
        private final Boolean indexUnclassifiedEvents;
        private final Boolean indexDiscardedEvents;
        private final List<String> enrichments;

        /**
         * @param enabled the policy's {@code enabled} flag, or {@code null} if undecided.
         * @param indexUnclassifiedEvents the {@code index_unclassified_events} flag, or {@code null}.
         * @param indexDiscardedEvents the {@code index_discarded_events} flag, or {@code null}.
         * @param enrichments the enrichments the user kept, or {@code null} if they never chose. An
         *     empty list is a choice; {@code null} is the absence of one.
         */
        public PolicySettings(
                Boolean enabled,
                Boolean indexUnclassifiedEvents,
                Boolean indexDiscardedEvents,
                List<String> enrichments) {
            this.enabled = enabled;
            this.indexUnclassifiedEvents = indexUnclassifiedEvents;
            this.indexDiscardedEvents = indexDiscardedEvents;
            this.enrichments = enrichments;
        }

        /**
         * @return the {@code enabled} flag the user chose, or {@code null} if undecided.
         */
        public Boolean getEnabled() {
            return this.enabled;
        }

        /**
         * @return the {@code index_unclassified_events} flag the user chose, or {@code null}.
         */
        public Boolean getIndexUnclassifiedEvents() {
            return this.indexUnclassifiedEvents;
        }

        /**
         * @return the {@code index_discarded_events} flag the user chose, or {@code null}.
         */
        public Boolean getIndexDiscardedEvents() {
            return this.indexDiscardedEvents;
        }

        /**
         * @return the enrichments the user kept, or {@code null} if they never changed the selection.
         */
        public List<String> getEnrichments() {
            return this.enrichments;
        }

        /**
         * @param node the stored {@code policy} node.
         * @return the settings it holds, with absent fields left {@code null}.
         */
        static PolicySettings from(JsonNode node) {
            // Absence and emptiness are different: no list means the user never chose and CTI decides,
            // an empty one means they unchecked everything.
            List<String> enrichments = null;
            if (node.has(Constants.KEY_ENRICHMENTS)) {
                enrichments = new ArrayList<>();
                for (JsonNode entry : node.get(Constants.KEY_ENRICHMENTS)) {
                    enrichments.add(entry.asText());
                }
            }
            return new PolicySettings(
                    node.has(Constants.KEY_ENABLED) ? node.get(Constants.KEY_ENABLED).asBoolean() : null,
                    node.has(Constants.KEY_INDEX_UNCLASSIFIED_EVENTS)
                            ? node.get(Constants.KEY_INDEX_UNCLASSIFIED_EVENTS).asBoolean()
                            : null,
                    node.has(Constants.KEY_INDEX_DISCARDED_EVENTS)
                            ? node.get(Constants.KEY_INDEX_DISCARDED_EVENTS).asBoolean()
                            : null,
                    enrichments);
        }

        /**
         * @param factory any node from the target document, used only as a node factory.
         * @return these settings as a node, omitting the fields the user never decided.
         */
        ObjectNode toNode(ObjectNode factory) {
            ObjectNode node = factory.objectNode();
            if (this.enabled != null) {
                node.put(Constants.KEY_ENABLED, this.enabled.booleanValue());
            }
            if (this.indexUnclassifiedEvents != null) {
                node.put(
                        Constants.KEY_INDEX_UNCLASSIFIED_EVENTS, this.indexUnclassifiedEvents.booleanValue());
            }
            if (this.indexDiscardedEvents != null) {
                node.put(Constants.KEY_INDEX_DISCARDED_EVENTS, this.indexDiscardedEvents.booleanValue());
            }
            if (this.enrichments != null) {
                ArrayNode list = factory.arrayNode();
                this.enrichments.forEach(list::add);
                node.set(Constants.KEY_ENRICHMENTS, list);
            }
            return node;
        }
    }

    /**
     * A filter the user created, kept as a serialized JSON string.
     *
     * <p>A string, not a nested object: the policies mapping is {@code dynamic: true}, so nesting a
     * filter's fields there would auto-map every field of every stored filter into the policies
     * index, and two filters with conflicting field types would make the write fail outright.
     */
    public static final class StoredFilter {

        private final String id;
        private final String document;

        /**
         * @param id the filter's document id, reused when it is recreated.
         * @param document the filter's full stored document, serialized.
         */
        public StoredFilter(String id, String document) {
            this.id = id;
            this.document = document;
        }

        /**
         * @return the filter's document id.
         */
        public String getId() {
            return this.id;
        }

        /**
         * @return the filter's full stored document, serialized.
         */
        public String getDocument() {
            return this.document;
        }
    }

    /**
     * The user's decision about one integration's enabled state.
     *
     * <p>Held here rather than on the integration document because the rebuild deletes those
     * documents before writing the new ones, so nothing written on them survives.
     *
     * <p>Only the decision is stored, not the whole document: unlike a filter, the integration itself
     * comes from CTI and is recreated by the rebuild.
     */
    public static final class IntegrationOverride {

        private final String id;
        private final Boolean enabled;

        /**
         * @param id the integration's document id.
         * @param enabled the state the user chose.
         */
        public IntegrationOverride(String id, Boolean enabled) {
            this.id = id;
            this.enabled = enabled;
        }

        /**
         * @return the integration's document id.
         */
        public String getId() {
            return this.id;
        }

        /**
         * @return the state the user chose.
         */
        public Boolean getEnabled() {
            return this.enabled;
        }
    }
}
