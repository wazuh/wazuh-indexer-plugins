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
package com.wazuh.contentmanager.integration;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugins.Plugin;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Objects;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.synchronizer.RulesetConsumerSynchronizer;

/**
 * Integration test that verifies space initialization does not create duplicate policy documents
 * when the post-sync workflow runs multiple times, as would happen in a multi-node cluster where
 * each node triggers {@code onSyncComplete(true)} after a successful synchronization.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE, numDataNodes = 2)
public class SpaceInitializationIT extends OpenSearchIntegTestCase {

    private static final String INDEX_POLICIES = ".cti-policies";
    private static final String Q_SPACE_NAME = "space.name";
    private static final String[] SPACE_NAMES = {"draft", "test", "custom"};

    private static final Map<String, String> INDEX_MAPPINGS =
            Map.of(
                    ".cti-rules", "/mappings/cti-rules-mappings.json",
                    ".cti-decoders", "/mappings/cti-decoders-mappings.json",
                    ".cti-kvdbs", "/mappings/cti-kvdbs-mappings.json",
                    ".cti-integrations", "/mappings/cti-integrations-mappings.json",
                    ".engine-filters", "/mappings/engine-filters-mappings.json",
                    ".cti-policies", "/mappings/cti-policies-mappings.json");

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
     * <p>Expected result: exactly 3 policy documents in {@code .cti-policies} (one per space: draft,
     * test, custom), regardless of how many times the workflow runs.
     */
    public void testOnSyncCompleteDoesNotDuplicateSpaces() throws Exception {
        ensureGreen();

        // Create all content indices required by onSyncComplete
        createContentIndices();

        // Instantiate the synchronizer with the test cluster's dependencies
        RulesetConsumerSynchronizer synchronizer =
                new RulesetConsumerSynchronizer(
                        client(),
                        new ConsumersIndex(client()),
                        internalCluster().getInstance(Environment.class));

        // First call — simulates the cluster manager node completing a sync
        synchronizer.onSyncComplete(true);

        // Second call — simulates a second node completing a sync
        synchronizer.onSyncComplete(true);

        // Refresh to make all documents searchable
        client().admin().indices().prepareRefresh(INDEX_POLICIES).get();

        // Assert exactly 3 total policy documents
        SearchResponse totalResponse =
                client()
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
                    client()
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

    /** Creates all content indices required by the post-sync workflow with their proper mappings. */
    private void createContentIndices() throws Exception {
        Settings indexSettings =
                Settings.builder()
                        .put("index.number_of_replicas", 0)
                        .put("index.number_of_shards", 1)
                        .build();

        for (Map.Entry<String, String> entry : INDEX_MAPPINGS.entrySet()) {
            String indexName = entry.getKey();
            String mappingPath = entry.getValue();

            String mapping;
            try (InputStream is = getClass().getResourceAsStream(mappingPath)) {
                assertNotNull("Could not find mapping resource: " + mappingPath, is);
                mapping = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            }

            CreateIndexRequest request =
                    new CreateIndexRequest().index(indexName).mapping(mapping).settings(indexSettings);

            assertTrue(
                    "Failed to create index " + indexName,
                    client().admin().indices().create(request).actionGet().isAcknowledged());
        }

        ensureGreen();
    }
}
