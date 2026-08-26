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
package com.wazuh.contentmanager;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugins.Plugin;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.After;

import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.service.ConsumerRulesetService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Integration test that verifies space initialization does not create duplicate policy documents
 * when the post-sync workflow runs multiple times, as would happen in a multi-node cluster where
 * each node triggers {@code onSyncComplete(true)} after a successful synchronization.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE, numDataNodes = 2)
public class SpaceInitializationIT extends OpenSearchIntegTestCase {

    private static final String INDEX_POLICIES = "wazuh-threatintel-policies";
    private static final String Q_SPACE_NAME = "space.name";
    private static final String[] SPACE_NAMES = {"draft", "test", "custom"};

    private static final List<String> CONTENT_INDICES =
            List.of(
                    "wazuh-threatintel-rules",
                    "wazuh-threatintel-decoders",
                    "wazuh-threatintel-kvdbs",
                    "wazuh-threatintel-integrations",
                    INDEX_POLICIES);

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
     * Verifies that running the full post-sync workflow ({@code onSyncComplete(true)}) twice does not
     * produce duplicate policy documents. This simulates the scenario where two nodes in a cluster
     * both complete a synchronization and trigger the post-sync operations.
     *
     * <p>Expected result: exactly 3 policy documents in {@code wazuh-threatintel-policies} (one per
     * space: draft, test, custom), regardless of how many times the workflow runs.
     */
    public void testOnSyncCompleteDoesNotDuplicateSpaces() throws Exception {
        this.ensureGreen(TimeValue.timeValueMinutes(2));

        // The plugin provisions the content indices onSyncComplete needs; wait for them.
        this.awaitContentIndices();

        // Initialize PluginSettings in the test JVM (the plugin runs in the external cluster JVM)
        PluginSettings.getInstance(
                Settings.builder().put("plugins.content_manager.catalog.create_detectors", false).build());

        // Instantiate the synchronizer with the test cluster's client.
        // Environment and ConsumersIndex are only used by syncConsumerServices(), not onSyncComplete().
        ConsumerRulesetService synchronizer =
                new ConsumerRulesetService(
                        OpenSearchIntegTestCase.client(),
                        new ConsumersIndex(OpenSearchIntegTestCase.client()),
                        null,
                        new SpaceService(OpenSearchIntegTestCase.client()),
                        null);

        // First call — simulates the cluster manager node completing a sync
        synchronizer.onSyncComplete(true);

        // Second call — simulates a second node completing a sync
        synchronizer.onSyncComplete(true);

        // Refresh to make all documents searchable
        OpenSearchIntegTestCase.client().admin().indices().prepareRefresh(INDEX_POLICIES).get();

        // Assert exactly 3 total policy documents
        SearchResponse totalResponse =
                OpenSearchIntegTestCase.client()
                        .search(
                                new SearchRequest(INDEX_POLICIES)
                                        .source(new SearchSourceBuilder().query(QueryBuilders.matchAllQuery()).size(0)))
                        .actionGet();

        long totalHits = Objects.requireNonNull(totalResponse.getHits().getTotalHits()).value();
        assertEquals(
                "Expected exactly 3 policy documents total, but found " + totalHits, 3L, totalHits);

        // Assert exactly 1 document per space
        for (String spaceName : SPACE_NAMES) {
            SearchResponse spaceResponse =
                    OpenSearchIntegTestCase.client()
                            .search(
                                    new SearchRequest(INDEX_POLICIES)
                                            .source(
                                                    new SearchSourceBuilder()
                                                            .query(QueryBuilders.termQuery(Q_SPACE_NAME, spaceName))
                                                            .size(0)))
                            .actionGet();

            long spaceHits = Objects.requireNonNull(spaceResponse.getHits().getTotalHits()).value();
            assertEquals(
                    "Expected exactly 1 policy document for space ["
                            + spaceName
                            + "], but found "
                            + spaceHits,
                    1L,
                    spaceHits);
        }
    }

    @After
    public void clearFieldData() {
        OpenSearchIntegTestCase.client()
                .admin()
                .indices()
                .prepareClearCache()
                .setFieldDataCache(true)
                .get();
    }

    /**
     * Waits for the content indices the post-sync workflow needs.
     *
     * <p>This test connects to the Gradle test cluster as an {@code ExternalTestCluster}, so {@link
     * #nodePlugins()} does not apply and both the Setup and Content Manager plugins are running
     * there. Each of these indices is provisioned as {@code <name>-a} with the public alias {@code
     * <name>} pointing at it, by the Setup plugin. Creating them here as concrete indices named after
     * the aliases therefore fails with "invalid index name [...], already exists as alias": a
     * concrete index cannot take a name an alias already holds. Wait for them instead.
     */
    private void awaitContentIndices() throws Exception {
        assertBusy(
                () -> {
                    for (String indexName : CONTENT_INDICES) {
                        assertTrue(
                                "Index " + indexName + " was not provisioned by the plugin",
                                OpenSearchIntegTestCase.client()
                                        .admin()
                                        .indices()
                                        .prepareExists(indexName)
                                        .get()
                                        .isExists());
                    }
                },
                2,
                TimeUnit.MINUTES);
        this.ensureGreen();
    }
}
