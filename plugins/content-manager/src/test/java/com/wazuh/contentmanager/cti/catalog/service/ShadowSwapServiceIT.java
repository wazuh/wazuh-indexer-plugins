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
package com.wazuh.contentmanager.cti.catalog.service;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.admin.indices.alias.get.GetAliasesResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.cluster.metadata.AliasMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.Environment;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.After;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicBoolean;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.catalog.client.ResourceUrlResolver;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.mock;

/**
 * Integration test for the swap of several consumers at once, on a real cluster: the aliases of
 * every consumer that changes data source switch in one operation, and a swap that fails before the
 * switch leaves every consumer on its content.
 *
 * <p>The consumers use their own aliases, created here on the {@code -a} slot, and their own types
 * in {@code .wazuh-cti-consumers}, so the content of the cluster is left alone. They hold no user
 * content: copying it needs the reindex module, which the test cluster does not load.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE, numDataNodes = 2)
public class ShadowSwapServiceIT extends OpenSearchIntegTestCase {

    private static final String PREFIX = "swap-it-";
    private static final String RULES = PREFIX + "rules";
    private static final String DECODERS = PREFIX + "decoders";
    private static final String IOCS = PREFIX + "iocs";
    private static final String CVES = PREFIX + "cves";
    private static final List<String> ALIASES = List.of(RULES, DECODERS, IOCS, CVES);

    private static final String RULESET_TYPE = "it:swap:ruleset";
    private static final String IOCS_TYPE = "it:swap:iocs";
    private static final String CVES_TYPE = "it:swap:vulnerabilities";

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Collections.singletonList(ContentManagerPlugin.class);
    }

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        return Settings.builder()
                .put(super.nodeSettings(nodeOrdinal))
                .put("plugins.content_manager.catalog.update_on_start", false)
                .put("plugins.content_manager.catalog.update_on_schedule", false)
                .put("plugins.content_manager.catalog.create_detectors", false)
                .build();
    }

    /**
     * Three consumers change data source: every alias switches in the same operation, as a reader
     * polling the aliases throughout sees, the previous indices are deleted, and the consumer
     * documents end on the new data sources.
     */
    public void testChangingConsumersSwitchInOneOperation() throws Exception {
        List<ItConsumer> consumers = this.setUpConsumers();
        SyncPass pass = SyncPass.withPlan(plan());

        Set<String> observed = Collections.synchronizedSet(new LinkedHashSet<>());
        AtomicBoolean swapping = new AtomicBoolean(true);
        Thread reader =
                new Thread(
                        () -> {
                            while (swapping.get()) {
                                observed.add(this.slots());
                            }
                        });
        reader.start();
        try {
            new ShadowSwapService(client(), this.consumersIndex()).swapChangedSources(consumers, pass);
        } finally {
            swapping.set(false);
            reader.join();
        }

        for (String combination : observed) {
            assertTrue(
                    "A reader saw a mix of slots: " + combination,
                    Set.of("a,a,a,a", "b,b,b,b").contains(combination));
        }
        assertEquals("b,b,b,b", this.slots());
        for (String alias : ALIASES) {
            assertFalse(indexExists(alias + ContentIndex.SUFFIX_A));
        }
        for (String type : List.of(RULESET_TYPE, IOCS_TYPE, CVES_TYPE)) {
            assertEquals(SyncPass.SwapOutcome.SWAPPED, pass.swapOutcome(type));
            LocalConsumer document = consumers.get(0).read(type);
            assertEquals(resource("pro-" + suffix(type)), document.getResource());
            assertEquals(LocalConsumer.Status.RUNNING, document.getStatus());
            assertEquals(90, document.getLocalOffset());
            assertEquals(100, document.getRemoteOffset());
        }
        for (String alias : ALIASES) {
            assertEquals(
                    "The new content of [" + alias + "] is searchable as soon as it is switched",
                    1,
                    this.searchHits(alias));
        }
        assertFalse("The previous standard rule is gone", this.documentExists(RULES, "old-standard"));
        assertTrue(this.documentExists(RULES, "new-" + RULES));
        assertTrue(this.documentExists(DECODERS, "new-" + DECODERS));
        assertTrue(this.documentExists(IOCS, "new-" + IOCS));
        assertTrue(this.documentExists(CVES, "new-" + CVES));
    }

    /**
     * The last consumer's snapshot cannot be loaded: no alias switches, the staging indices are
     * deleted and every consumer document is back on its previous data source.
     */
    public void testFailedLoadKeepsEveryConsumerOnItsContent() throws Exception {
        List<ItConsumer> consumers = this.setUpConsumers();
        consumers.get(2).loadSucceeds = false;
        SyncPass pass = SyncPass.withPlan(plan());

        new ShadowSwapService(client(), this.consumersIndex()).swapChangedSources(consumers, pass);

        assertEquals("a,a,a,a", this.slots());
        for (String alias : ALIASES) {
            assertFalse(indexExists(alias + ContentIndex.SUFFIX_B));
        }
        for (String type : List.of(RULESET_TYPE, IOCS_TYPE, CVES_TYPE)) {
            assertEquals(SyncPass.SwapOutcome.PENDING, pass.swapOutcome(type));
            LocalConsumer document = consumers.get(0).read(type);
            assertEquals(resource("open-" + suffix(type)), document.getResource());
            assertEquals(LocalConsumer.Status.READY, document.getStatus());
        }
        assertTrue(this.documentExists(RULES, "old-standard"));
    }

    /** Each test starts from its own aliases and consumer documents. */
    @After
    public void deleteTestIndices() throws Exception {
        for (String alias : ALIASES) {
            for (String suffix : List.of(ContentIndex.SUFFIX_A, ContentIndex.SUFFIX_B)) {
                try {
                    client().admin().indices().prepareDelete(alias + suffix).get();
                } catch (IndexNotFoundException e) {
                    // Nothing to clean up.
                }
            }
        }
        for (String type : List.of(RULESET_TYPE, IOCS_TYPE, CVES_TYPE)) {
            client()
                    .prepareDelete(ConsumersIndex.INDEX_NAME, type)
                    .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                    .get();
        }
    }

    /**
     * Creates the consumers on the open feed: their aliases on the {@code -a} slot, with one document
     * each, and their documents synced at offset 50.
     */
    private List<ItConsumer> setUpConsumers() throws Exception {
        this.ensureGreen(TimeValue.timeValueMinutes(2));
        PluginSettings.getInstance(Settings.EMPTY);
        ConsumersIndex consumersIndex = this.consumersIndex();
        consumersIndex.createIndex();

        Map<String, String> mappings = new LinkedHashMap<>();
        mappings.put(RULES, "/mappings/cti-rules-mappings.json");
        mappings.put(DECODERS, "/mappings/cti-decoders-mappings.json");
        mappings.put(IOCS, "/mappings/cti-ioc-mappings.json");
        mappings.put(CVES, "/mappings/cti-cve-mappings.json");
        for (Map.Entry<String, String> entry : mappings.entrySet()) {
            new ContentIndex(client(), entry.getKey(), entry.getValue()).createIndex();
        }
        this.index(RULES + ContentIndex.SUFFIX_A, "old-standard", "standard");
        this.index(DECODERS + ContentIndex.SUFFIX_A, "old-standard", "standard");
        client()
                .prepareIndex(IOCS + ContentIndex.SUFFIX_A)
                .setId("old-ioc")
                .setSource("{\"document\":{\"id\":\"old-ioc\"}}", XContentType.JSON)
                .get();
        client()
                .prepareIndex(CVES + ContentIndex.SUFFIX_A)
                .setId("old-cve")
                .setSource("{\"offset\":1}", XContentType.JSON)
                .get();
        client().admin().indices().prepareRefresh(RULES, DECODERS, IOCS, CVES).get();

        List<ItConsumer> consumers =
                List.of(
                        new ItConsumer(
                                consumersIndex,
                                RULESET_TYPE,
                                Map.of(RULES, mappings.get(RULES), DECODERS, mappings.get(DECODERS))),
                        new ItConsumer(consumersIndex, IOCS_TYPE, Map.of(IOCS, mappings.get(IOCS))),
                        new ItConsumer(consumersIndex, CVES_TYPE, Map.of(CVES, mappings.get(CVES))));
        List<LocalConsumer> documents = new ArrayList<>();
        for (ItConsumer consumer : consumers) {
            String name = "open-" + suffix(consumer.getConsumerType());
            documents.add(
                    new LocalConsumer(
                            name,
                            name,
                            consumer.getConsumerType(),
                            resource(name),
                            true,
                            LocalConsumer.Status.READY,
                            50,
                            50));
        }
        consumersIndex.setConsumers(documents);
        return consumers;
    }

    /** Returns the slot each alias points at, in {@link #ALIASES} order, e.g. {@code "a,a,a,a"}. */
    private String slots() {
        GetAliasesResponse response =
                client().admin().indices().prepareGetAliases(ALIASES.toArray(new String[0])).get();
        Map<String, String> slotByAlias = new LinkedHashMap<>();
        for (Map.Entry<String, List<AliasMetadata>> entry : response.getAliases().entrySet()) {
            for (AliasMetadata alias : entry.getValue()) {
                slotByAlias.put(alias.alias(), entry.getKey().substring(entry.getKey().length() - 1));
            }
        }
        return String.join(",", ALIASES.stream().map(a -> slotByAlias.getOrDefault(a, "?")).toList());
    }

    private void index(String index, String id, String space) {
        client()
                .prepareIndex(index)
                .setId(id)
                .setSource(
                        "{\"document\":{\"id\":\"" + id + "\"},\"space\":{\"name\":\"" + space + "\"}}",
                        XContentType.JSON)
                .get();
    }

    /** Counts the documents a search finds, which unlike a get sees only refreshed content. */
    private long searchHits(String index) {
        return client().prepareSearch(index).setSize(0).get().getHits().getTotalHits().value();
    }

    private boolean documentExists(String index, String id) {
        return client().prepareGet(index, id).get().isExists();
    }

    private ConsumersIndex consumersIndex() {
        return new ConsumersIndex(client());
    }

    private static String suffix(String type) {
        return type.substring(type.lastIndexOf(':') + 1);
    }

    private static String resource(String name) {
        return "https://cti.example/api/v1/catalog/contexts/" + name + "/consumers/" + name;
    }

    /** A plan that moves the three consumers to the pro feed. */
    private static Plan plan() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode plan = mapper.createObjectNode().put("name", "Pro").put("is_public", false);
        ArrayNode features = plan.putArray("features");
        for (String type : List.of(RULESET_TYPE, IOCS_TYPE, CVES_TYPE)) {
            features.addObject().put("type", type).put("resource", resource("pro-" + suffix(type)));
        }
        return mapper.convertValue(plan, Plan.class);
    }

    /**
     * A consumer over the test aliases. Its new data source is at offset 100 with a snapshot at 90,
     * and loading the snapshot writes one document into each of its staging indices.
     */
    private static class ItConsumer extends AbstractConsumerService {
        private final String type;
        private final Map<String, String> mappings;
        boolean loadSucceeds = true;

        ItConsumer(ConsumersIndex consumersIndex, String type, Map<String, String> mappings) {
            super(client(), consumersIndex, mock(Environment.class));
            this.type = type;
            this.mappings = new LinkedHashMap<>(mappings);
            String name = "pro-" + suffix(type);
            RemoteConsumer remote =
                    new RemoteConsumer(
                            new ObjectMapper()
                                    .createObjectNode()
                                    .put("name", name)
                                    .put("context", name)
                                    .put("last_offset", 100)
                                    .put("last_snapshot_link", "https://cti.example/" + name + ".zip")
                                    .put("last_snapshot_offset", 90)
                                    .put("is_public", false),
                            type,
                            resource(name));
            this.setConsumerService(
                    new ConsumerService() {
                        @Override
                        public LocalConsumer getLocalConsumer() {
                            return null;
                        }

                        @Override
                        public RemoteConsumer getRemoteConsumer() {
                            return remote;
                        }

                        @Override
                        public void close() {}
                    });
        }

        LocalConsumer read(String consumerType) throws Exception {
            return new ObjectMapper()
                    .readValue(
                            this.consumersIndex.getConsumer(consumerType).getSourceAsString(),
                            LocalConsumer.class);
        }

        @Override
        protected String getConsumerType() {
            return this.type;
        }

        @Override
        protected String getCustomCatalogUri() {
            return "";
        }

        @Override
        protected Map<String, String> getMappings() {
            return this.mappings;
        }

        @Override
        public String getIndexName(String type) {
            return type;
        }

        @Override
        protected String getSnapshotFilename() {
            return "it.zip";
        }

        @Override
        public void onSyncComplete(boolean isUpdated) {}

        @Override
        boolean loadStagedSnapshot(
                Map<String, ContentIndex> stagingIndices,
                RemoteConsumer remoteConsumer,
                ResourceUrlResolver urlResolver) {
            if (!this.loadSucceeds) {
                return false;
            }
            String[] physical =
                    stagingIndices.values().stream()
                            .map(ContentIndex::getPhysicalName)
                            .toArray(String[]::new);
            // As under a large load, nothing refreshes the documents on its own before the switch.
            client()
                    .admin()
                    .indices()
                    .prepareUpdateSettings(physical)
                    .setSettings(Settings.builder().put("index.refresh_interval", "-1"))
                    .get();
            for (ContentIndex staging : stagingIndices.values()) {
                String id = "new-" + staging.getIndexName();
                String source =
                        switch (staging.getIndexName()) {
                            case CVES -> "{\"offset\":90}";
                            case IOCS -> "{\"document\":{\"id\":\"" + id + "\"}}";
                            default -> "{\"document\":{\"id\":\"" + id + "\"},\"space\":{\"name\":\"standard\"}}";
                        };
                client()
                        .prepareIndex(staging.getPhysicalName())
                        .setId(id)
                        .setSource(source, XContentType.JSON)
                        .get();
            }
            return true;
        }
    }
}
