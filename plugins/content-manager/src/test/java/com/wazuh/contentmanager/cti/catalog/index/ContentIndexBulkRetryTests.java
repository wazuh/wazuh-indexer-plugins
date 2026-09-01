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
package com.wazuh.contentmanager.cti.catalog.index;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.bulk.BulkResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Reproduces, against a real OpenSearch cluster, the bulk indexing failure reported during the
 * 5.0.0 Central Components DTT run and validates that the retry added to {@link ContentIndex}
 * recovers the documents the cluster sheds.
 *
 * <p>The DTT failure was a parent circuit breaker trip on the node holding the single primary shard
 * of {@code .wazuh-threatintel-vulnerabilities-a}. The trigger there was real heap pressure, which
 * is not reproducible on demand; the breaker is instead driven deterministically here by accounting
 * reserved bytes ({@code indices.breaker.total.use_real_memory: false}) and lowering {@code
 * indices.breaker.total.limit} so that any bulk trips it. The resulting failure delivered to the
 * client is the same {@code CircuitBreakingException}, exercising the same code path.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(
        scope = OpenSearchIntegTestCase.Scope.TEST,
        numDataNodes = 2,
        supportsDedicatedMasters = false)
public class ContentIndexBulkRetryTests extends OpenSearchIntegTestCase {

    private static final Logger log = LogManager.getLogger(ContentIndexBulkRetryTests.class);

    private static final String INDEX = "wazuh-threatintel-vulnerabilities-a";
    private static final String PARENT_BREAKER_LIMIT = "indices.breaker.total.limit";

    /** Documents per bulk, mirroring a slice of the CVE catalog the DTT run was loading. */
    private static final int DOCUMENT_COUNT = 50;

    @Override
    protected Settings nodeSettings(int nodeOrdinal) {
        return Settings.builder()
                .put(super.nodeSettings(nodeOrdinal))
                // Account reserved bytes instead of real heap, so the trip point is deterministic.
                .put("indices.breaker.total.use_real_memory", false)
                .build();
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(Settings.builder().build());
        // Several shards over two nodes guarantees at least one shard-level bulk leaves the
        // coordinating node, the hop that reserves in_flight_requests against the parent breaker.
        createIndex(
                INDEX,
                Settings.builder()
                        .put("index.number_of_shards", 4)
                        .put("index.number_of_replicas", 0)
                        .build());
        ensureGreen(INDEX);
    }

    /** Lowers or restores the parent circuit breaker limit on the live cluster. */
    private void setParentBreakerLimit(String limit) {
        boolean acked =
                client()
                        .admin()
                        .cluster()
                        .prepareUpdateSettings()
                        .setPersistentSettings(Settings.builder().put(PARENT_BREAKER_LIMIT, limit))
                        .get()
                        .isAcknowledged();
        assertTrue("breaker limit update was not acknowledged", acked);
        log.info("[VALIDATION] parent circuit breaker limit set to [{}]", limit);
    }

    private static BulkRequest cveBulk(int count) {
        BulkRequest request = new BulkRequest();
        for (int i = 0; i < count; i++) {
            request.add(
                    new IndexRequest(INDEX)
                            .id("CVE-2024-" + (10000 + i))
                            .source(
                                    "{\"name\":\"CVE-2024-"
                                            + (10000 + i)
                                            + "\",\"description\":\""
                                            + "x".repeat(2048)
                                            + "\"}",
                                    XContentType.JSON));
        }
        return request;
    }

    private long indexedDocuments() {
        client().admin().indices().prepareRefresh(INDEX).get();
        return client().prepareSearch(INDEX).setSize(0).get().getHits().getTotalHits().value();
    }

    /**
     * Confirms the cluster really does shed the bulk, and captures the failure exactly as the content
     * manager receives it. This is the condition the DTT run hit.
     */
    public void testCircuitBreakerShedsBulkWrites() throws Exception {
        this.setParentBreakerLimit("1kb");

        CountDownLatch latch = new CountDownLatch(1);
        AtomicReference<String> failure = new AtomicReference<>();
        client()
                .bulk(
                        cveBulk(DOCUMENT_COUNT),
                        ActionListener.wrap(
                                response -> {
                                    if (response.hasFailures()) {
                                        failure.set(response.buildFailureMessage());
                                    }
                                    latch.countDown();
                                },
                                e -> {
                                    failure.set(e.toString());
                                    latch.countDown();
                                }));
        assertTrue("bulk did not complete", latch.await(30, TimeUnit.SECONDS));
        this.setParentBreakerLimit("70%");

        assertNotNull("expected the cluster to shed the bulk", failure.get());
        log.info(
                "[VALIDATION] observed shed failure (first line): {}",
                failure.get().lines().findFirst().orElse(""));
        log.info(
                "[VALIDATION] observed shed failure (first item): {}",
                failure.get().lines().skip(1).findFirst().orElse(""));
        assertTrue(
                "expected a CircuitBreakingException, got: " + failure.get(),
                failure.get().contains("circuit_breaking_exception")
                        || failure.get().contains("CircuitBreakingException"));

        long indexed = this.indexedDocuments();
        log.info(
                "[VALIDATION] {} documents submitted, {} indexed, {} shed",
                DOCUMENT_COUNT,
                indexed,
                DOCUMENT_COUNT - indexed);
        assertTrue("expected part of the bulk to be shed", indexed < DOCUMENT_COUNT);
    }

    /**
     * Baseline: the pre-fix fire-and-forget behaviour. The body below is the original {@code
     * executeBulk} listener -- it logs the failure and moves on -- and shows the documents are lost
     * for good.
     */
    public void testFireAndForgetLosesShedDocuments() throws Exception {
        this.setParentBreakerLimit("1kb");

        CountDownLatch latch = new CountDownLatch(1);
        client()
                .bulk(
                        cveBulk(DOCUMENT_COUNT),
                        new ActionListener<>() {
                            @Override
                            public void onResponse(BulkResponse bulkResponse) {
                                if (bulkResponse.hasFailures()) {
                                    // This is what the plugin used to do: log and drop.
                                    log.warn(
                                            "[VALIDATION][pre-fix] Bulk indexing finished with failures: {}",
                                            bulkResponse.buildFailureMessage().lines().findFirst().orElse(""));
                                }
                                latch.countDown();
                            }

                            @Override
                            public void onFailure(Exception e) {
                                log.error("[VALIDATION][pre-fix] Bulk index operation failed: {}", e.getMessage());
                                latch.countDown();
                            }
                        });
        assertTrue("bulk did not complete", latch.await(30, TimeUnit.SECONDS));

        // Pressure clears, exactly as it did on node-9 once G1GC ran.
        this.setParentBreakerLimit("70%");
        Thread.sleep(2000);

        long indexed = this.indexedDocuments();
        log.info(
                "[VALIDATION][pre-fix] {} documents submitted, {} indexed -- {} lost for good",
                DOCUMENT_COUNT,
                indexed,
                DOCUMENT_COUNT - indexed);
        assertTrue(
                "pre-fix behaviour: shed documents are never re-submitted, so some must be missing",
                indexed < DOCUMENT_COUNT);
    }

    /**
     * The fix: {@link ContentIndex#executeBulk} re-submits what the cluster shed, so once the
     * pressure clears every document lands and nothing is reported as dropped.
     */
    public void testExecuteBulkRecoversShedDocuments() throws Exception {
        ContentIndex contentIndex = new ContentIndex(client(), INDEX);

        this.setParentBreakerLimit("1kb");
        contentIndex.executeBulk(cveBulk(DOCUMENT_COUNT));

        // Let the first attempt be shed, then clear the pressure while the retry is pending.
        Thread.sleep(500);
        this.setParentBreakerLimit("70%");

        contentIndex.waitForPendingUpdates();

        long indexed = this.indexedDocuments();
        log.info(
                "[VALIDATION][post-fix] {} documents submitted, {} indexed, {} dropped",
                DOCUMENT_COUNT,
                indexed,
                contentIndex.getDroppedDocuments());

        assertEquals("every shed document must be recovered by the retry", DOCUMENT_COUNT, indexed);
        assertEquals("nothing should be reported as dropped", 0L, contentIndex.getDroppedDocuments());
    }

    /**
     * When the pressure never clears, the documents are still lost -- but they are now counted, which
     * is what lets the snapshot loader refuse to advance the consumer offset over the gap.
     */
    public void testExecuteBulkCountsDocumentsDroppedWhenPressureNeverClears() throws Exception {
        ContentIndex contentIndex = new ContentIndex(client(), INDEX);

        this.setParentBreakerLimit("1kb");
        contentIndex.executeBulk(cveBulk(DOCUMENT_COUNT));
        contentIndex.waitForPendingUpdates();

        long dropped = contentIndex.getDroppedDocuments();
        this.setParentBreakerLimit("70%");

        log.info(
                "[VALIDATION][post-fix] pressure sustained: {} documents submitted, {} indexed, {} dropped",
                DOCUMENT_COUNT,
                this.indexedDocuments(),
                dropped);

        long indexed = this.indexedDocuments();
        assertTrue("expected the cluster to shed part of the bulk", dropped > 0);
        assertEquals(
                "every document that did not land must be counted as dropped",
                DOCUMENT_COUNT - indexed,
                dropped);
    }
}
