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
import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

import com.wazuh.contentmanager.utils.Constants;

/**
 * The user's overrides for one space, as held in the registry document.
 *
 * <p>The {@code standard} space is rebuilt from CTI, so anything a user writes there needs an
 * explicit mechanism to survive: the rebuild replaces the policy document wholesale, and deletes
 * the filters and the integrations outright. All three therefore live here.
 *
 * <p>Absence is meaningful throughout: a {@code null} setting means the user never decided that
 * field and CTI keeps deciding it. Enrichments are held as a delta (the types the user turned off)
 * rather than as a list, so that values CTI publishes later still reach a user who customised the
 * selection.
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
            spaceNode
                    .get(Constants.KEY_INTEGRATION_OVERRIDES)
                    .properties()
                    .forEach(
                            entry ->
                                    overriddenIntegrations.add(
                                            new IntegrationOverride(
                                                    entry.getKey(),
                                                    readOptionalBoolean(entry.getValue(), Constants.KEY_ENABLED),
                                                    readOptionalBoolean(entry.getValue(), Constants.KEY_DETECTOR_ENABLED))));
        }
        return new UserOverrides(settings, stored, overriddenIntegrations);
    }

    /**
     * @param node the entry to read from.
     * @param field the field name.
     * @return the boolean it holds, or {@code null} when the field is absent — which throughout this
     *     registry means the user never decided, not {@code false}.
     */
    private static Boolean readOptionalBoolean(JsonNode node, String field) {
        return node.has(field) ? Boolean.valueOf(node.get(field).asBoolean()) : null;
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

        // Keyed by id, not an array: a partial `doc` update merges objects recursively but replaces
        // arrays wholesale, so this shape lets Security Analytics record one integration's detector
        // decision with a single call, without reading and rewriting the whole document.
        ObjectNode integrationsNode = registryRoot.objectNode();
        for (IntegrationOverride integration : this.integrations) {
            ObjectNode entry = registryRoot.objectNode();
            // Absent means undecided, so a null is omitted rather than written as null.
            if (integration.getEnabled() != null) {
                entry.put(Constants.KEY_ENABLED, integration.getEnabled().booleanValue());
            }
            if (integration.getDetectorEnabled() != null) {
                entry.put(Constants.KEY_DETECTOR_ENABLED, integration.getDetectorEnabled().booleanValue());
            }
            integrationsNode.set(integration.getId(), entry);
        }
        spaceNode.set(Constants.KEY_INTEGRATION_OVERRIDES, integrationsNode);

        registryRoot.set(spaceName, spaceNode);
    }

    /**
     * The four settings a user can change on the standard policy.
     *
     * <p>All four are recorded on every save, by design: editing the standard policy makes its
     * settings the user's from then on. A {@code null} field means the user never saved at all.
     *
     * <p>The enrichments are held as the types the user turned off, not as the list they kept, so a
     * type CTI publishes after the save still reaches the policy. Overrides written before that
     * change hold the kept list under {@code enrichments}; they are read as {@linkplain
     * #getLegacyEnrichments() legacy} and converted the first time they are applied or saved.
     */
    public static final class PolicySettings {

        private final Boolean enabled;
        private final Boolean indexUnclassifiedEvents;
        private final Boolean indexDiscardedEvents;
        private final List<String> disabledEnrichments;
        private final List<String> legacyEnrichments;

        /**
         * @param enabled the policy's {@code enabled} flag, or {@code null} if undecided.
         * @param indexUnclassifiedEvents the {@code index_unclassified_events} flag, or {@code null}.
         * @param indexDiscardedEvents the {@code index_discarded_events} flag, or {@code null}.
         * @param disabledEnrichments the enrichments the user turned off, or {@code null} if they never
         *     chose. An empty list is a choice (nothing is off); {@code null} is the absence of one.
         */
        public PolicySettings(
                Boolean enabled,
                Boolean indexUnclassifiedEvents,
                Boolean indexDiscardedEvents,
                List<String> disabledEnrichments) {
            this(enabled, indexUnclassifiedEvents, indexDiscardedEvents, disabledEnrichments, null);
        }

        private PolicySettings(
                Boolean enabled,
                Boolean indexUnclassifiedEvents,
                Boolean indexDiscardedEvents,
                List<String> disabledEnrichments,
                List<String> legacyEnrichments) {
            this.enabled = enabled;
            this.indexUnclassifiedEvents = indexUnclassifiedEvents;
            this.indexDiscardedEvents = indexDiscardedEvents;
            this.disabledEnrichments = disabledEnrichments;
            this.legacyEnrichments = disabledEnrichments == null ? legacyEnrichments : null;
        }

        /**
         * Settings in the format stored before the enrichments became a delta: the list of enrichments
         * the user kept.
         *
         * @param enabled the policy's {@code enabled} flag, or {@code null} if undecided.
         * @param indexUnclassifiedEvents the {@code index_unclassified_events} flag, or {@code null}.
         * @param indexDiscardedEvents the {@code index_discarded_events} flag, or {@code null}.
         * @param keptEnrichments the enrichments the user kept.
         * @return the settings, to be converted with {@link #withDisabledEnrichments(List)}.
         */
        public static PolicySettings legacy(
                Boolean enabled,
                Boolean indexUnclassifiedEvents,
                Boolean indexDiscardedEvents,
                List<String> keptEnrichments) {
            return new PolicySettings(
                    enabled, indexUnclassifiedEvents, indexDiscardedEvents, null, keptEnrichments);
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
         * @return the enrichments the user turned off, or {@code null} if they never changed the
         *     selection or the override is still in the legacy format.
         */
        public List<String> getDisabledEnrichments() {
            return this.disabledEnrichments;
        }

        /**
         * @return the enrichments the user kept, for an override stored in the legacy format; {@code
         *     null} otherwise.
         */
        public List<String> getLegacyEnrichments() {
            return this.legacyEnrichments;
        }

        /**
         * @return whether the override is still in the legacy format and must be converted.
         */
        public boolean isLegacy() {
            return this.legacyEnrichments != null;
        }

        /**
         * Resolves the enrichments the user turned off.
         *
         * <p>For a legacy override, those are the {@code candidates} missing from the list the user
         * kept. The candidates must be every type CTI publishes, as completely as the caller can tell.
         *
         * @param candidates the enrichment types CTI publishes; used only for a legacy override.
         * @return the types the user turned off, or {@code null} when the user never chose.
         */
        public List<String> resolveDisabledEnrichments(Collection<String> candidates) {
            if (this.legacyEnrichments == null) {
                return this.disabledEnrichments;
            }
            Set<String> disabled = new LinkedHashSet<>(candidates);
            disabled.removeAll(this.legacyEnrichments);
            return new ArrayList<>(disabled);
        }

        /**
         * @param disabled the enrichments the user turned off, or {@code null} if they never chose.
         * @return a copy of these settings with that delta, in the current format.
         */
        public PolicySettings withDisabledEnrichments(List<String> disabled) {
            return new PolicySettings(
                    this.enabled, this.indexUnclassifiedEvents, this.indexDiscardedEvents, disabled);
        }

        /**
         * @param node the stored {@code policy} node.
         * @return the settings it holds, with absent fields left {@code null}.
         */
        static PolicySettings from(JsonNode node) {
            // Absence and emptiness are different: no list means the user never chose and CTI decides,
            // an empty one means they turned nothing off.
            return new PolicySettings(
                    node.has(Constants.KEY_ENABLED) ? node.get(Constants.KEY_ENABLED).asBoolean() : null,
                    node.has(Constants.KEY_INDEX_UNCLASSIFIED_EVENTS)
                            ? node.get(Constants.KEY_INDEX_UNCLASSIFIED_EVENTS).asBoolean()
                            : null,
                    node.has(Constants.KEY_INDEX_DISCARDED_EVENTS)
                            ? node.get(Constants.KEY_INDEX_DISCARDED_EVENTS).asBoolean()
                            : null,
                    readList(node, Constants.KEY_DISABLED_ENRICHMENTS),
                    readList(node, Constants.KEY_ENRICHMENTS));
        }

        /**
         * @return the strings of the array under {@code field}, or {@code null} when it is absent.
         */
        private static List<String> readList(JsonNode node, String field) {
            if (!node.has(field)) {
                return null;
            }
            List<String> values = new ArrayList<>();
            for (JsonNode entry : node.get(field)) {
                values.add(entry.asText());
            }
            return values;
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
            if (this.disabledEnrichments != null) {
                ArrayNode list = factory.arrayNode();
                this.disabledEnrichments.forEach(list::add);
                node.set(Constants.KEY_DISABLED_ENRICHMENTS, list);
            } else if (this.legacyEnrichments != null) {
                // Written back as it was read, so a write of another section (a filter, an integration)
                // does not lose a legacy override before it is converted.
                ArrayNode list = factory.arrayNode();
                this.legacyEnrichments.forEach(list::add);
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
     * The user's decisions about one integration: its own enabled state, and its detector's.
     *
     * <p>Held here rather than on the integration document because the rebuild deletes those
     * documents before writing the new ones, so nothing written on them survives.
     *
     * <p>Only the decisions are stored, not the whole document: unlike a filter, the integration
     * itself comes from CTI and is recreated by the rebuild.
     *
     * <p>The two are independent and either may be absent. Stopping a detector must not fabricate an
     * opinion about its integration, because the override always wins over CTI and would disable an
     * integration nobody asked to disable.
     */
    public static final class IntegrationOverride {

        private final String id;
        private final Boolean enabled;
        private final Boolean detectorEnabled;

        /**
         * @param id the integration's document id.
         * @param enabled the state the user chose for the integration, or {@code null} if they never
         *     chose.
         * @param detectorEnabled the state the user chose for its detector, or {@code null} if they
         *     never chose, in which case CTI's {@code document.detector.enabled} decides.
         */
        public IntegrationOverride(String id, Boolean enabled, Boolean detectorEnabled) {
            this.id = id;
            this.enabled = enabled;
            this.detectorEnabled = detectorEnabled;
        }

        /**
         * @return the integration's document id.
         */
        public String getId() {
            return this.id;
        }

        /**
         * @return the state the user chose for the integration, or {@code null}.
         */
        public Boolean getEnabled() {
            return this.enabled;
        }

        /**
         * @return the state the user chose for its detector, or {@code null}.
         */
        public Boolean getDetectorEnabled() {
            return this.detectorEnabled;
        }
    }
}
