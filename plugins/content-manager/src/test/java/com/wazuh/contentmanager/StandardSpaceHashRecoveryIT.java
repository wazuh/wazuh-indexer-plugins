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

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.plugins.Plugin;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.After;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Integration test for wazuh/wazuh-indexer#1773: a node restarted while the standard space's {@code
 * space.hash.sha256} is being calculated leaves the cluster in a state where detectors in that
 * space stop producing findings.
 *
 * <p>The aggregate hash is written at the very end of a catalog sync, after the policy document
 * itself has been rewritten, so a restart inside that window persists a policy document with no
 * aggregate hash. Every node's {@code EngineContentLoader} then skips the standard space on the
 * missing hash, and nothing recalculates it: the consumer's local offset already matches the remote
 * one, so the next scheduled sync reports "no changes" and never reaches the recalculation step.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE, numDataNodes = 2)
public class StandardSpaceHashRecoveryIT extends OpenSearchIntegTestCase {

    private static final String INDEX_POLICIES = "wazuh-threatintel-policies";
    private static final String POLICIES_MAPPING = "/mappings/cti-policies-mappings.json";
    private static final String STANDARD = "standard";
    private static final String POLICY_ID = "c78194a8-e60e-4586-b098-b55f371291c3";

    /** The policy as the reporter's post-restart environment shows it: no space hash. */
    private static final String BROKEN_POLICY =
            "{"
                    + "\"document\":{\"id\":\""
                    + POLICY_ID
                    + "\",\"metadata\":{\"title\":\"RC1 public\"},"
                    + "\"integrations\":[],\"filters\":[],\"enabled\":true},"
                    + "\"hash\":{\"sha256\":\"88cb5e993448e24875a5e8e10db761d896119f19682f2ef641641a191d360d7d\"},"
                    + "\"space\":{\"name\":\""
                    + STANDARD
                    + "\"},"
                    + "\"offset\":1"
                    + "}";

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
     * A policy already persisted without an aggregate hash — the state a restart mid-sync leaves
     * behind — is recovered, and the recovery is idempotent.
     */
    public void testMissingStandardSpaceHashIsRecalculated() throws Exception {
        this.ensureGreen(TimeValue.timeValueMinutes(2));
        PluginSettings.getInstance(Settings.EMPTY);

        this.createPoliciesIndex();
        this.indexPolicy(BROKEN_POLICY);
        assertNull("Precondition: the policy must start without an aggregate hash", this.spaceHash());

        SpaceService spaceService = new SpaceService(OpenSearchIntegTestCase.client());

        PlainActionFuture<Set<String>> recovery = PlainActionFuture.newFuture();
        spaceService.recalculateSpaceHashIfMissing(STANDARD, recovery);
        assertEquals(
                "The standard space should be reported as changed so callers reload the Engine",
                Set.of(STANDARD),
                recovery.actionGet());

        OpenSearchIntegTestCase.client().admin().indices().prepareRefresh(INDEX_POLICIES).get();
        String recovered = this.spaceHash();
        assertNotNull("The aggregate hash should have been recalculated", recovered);
        assertFalse("The recalculated hash should not be blank", recovered.isBlank());

        // Idempotent: a healthy policy is left alone and nothing is reported as changed.
        PlainActionFuture<Set<String>> secondRun = PlainActionFuture.newFuture();
        spaceService.recalculateSpaceHashIfMissing(STANDARD, secondRun);
        assertTrue(
                "A policy that already has a hash must not be recalculated",
                secondRun.actionGet().isEmpty());

        OpenSearchIntegTestCase.client().admin().indices().prepareRefresh(INDEX_POLICIES).get();
        assertEquals("The existing hash must be left untouched", recovered, this.spaceHash());
    }

    /** The cluster is shared by the whole suite, so each test starts from a clean policies index. */
    @After
    public void deletePoliciesIndex() {
        try {
            OpenSearchIntegTestCase.client().admin().indices().prepareDelete(INDEX_POLICIES + "*").get();
        } catch (IndexNotFoundException e) {
            // Nothing to clean up.
        }
    }

    /** Reads {@code space.hash.sha256} of the standard policy, or null when absent. */
    @SuppressWarnings("unchecked")
    private String spaceHash() {
        SearchResponse response =
                OpenSearchIntegTestCase.client()
                        .search(
                                new SearchRequest(INDEX_POLICIES)
                                        .source(
                                                new SearchSourceBuilder()
                                                        .query(QueryBuilders.termQuery("space.name", STANDARD))
                                                        .size(1)))
                        .actionGet();
        assertEquals(
                "Expected exactly one standard policy document",
                1L,
                response.getHits().getTotalHits().value());

        Map<String, Object> space =
                (Map<String, Object>) response.getHits().getAt(0).getSourceAsMap().get("space");
        if (space == null) {
            return null;
        }
        Map<String, Object> hash = (Map<String, Object>) space.get("hash");
        return hash == null ? null : (String) hash.get("sha256");
    }

    private void indexPolicy(String source) {
        OpenSearchIntegTestCase.client()
                .index(
                        new IndexRequest(INDEX_POLICIES)
                                .id(POLICY_ID)
                                .source(source, XContentType.JSON)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }

    /**
     * Creates the physical policies index and its public alias through {@link ContentIndex}, so the
     * layout matches a real deployment ({@code wazuh-threatintel-policies-a} behind the {@code
     * wazuh-threatintel-policies} alias).
     *
     * <p>The index is dropped first. The cluster this test connects to runs the Setup plugin, which
     * provisions the index at node start, and the test needs an empty one: it asserts the policy it
     * writes is the only document and that it starts without an aggregate hash.
     */
    private void createPoliciesIndex() throws Exception {
        this.deletePoliciesIndex();
        ContentIndex policies =
                new ContentIndex(OpenSearchIntegTestCase.client(), INDEX_POLICIES, POLICIES_MAPPING);
        assertTrue("Failed to create index " + INDEX_POLICIES, policies.createIndex().isAcknowledged());
        this.ensureGreen();
    }
}
