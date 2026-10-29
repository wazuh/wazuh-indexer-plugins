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
package com.wazuh.contentmanager.cti.catalog.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.refresh.RefreshResponse;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.bulk.BulkItemResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.index.reindex.ReindexRequestBuilder;
import org.opensearch.index.reindex.ScrollableHitSource;
import org.opensearch.transport.client.Client;

import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Utility class for blue/green index swap operations. Provides methods to resolve shadow index
 * names, create shadow indices, reindex user content, perform atomic alias swaps, and clean up old
 * indices.
 *
 * <p>This class is stateless — all operations are static and receive the OpenSearch client as a
 * parameter so the logic is independently testable.
 */
public final class IndexSwapHelper {

    private static final Logger log = LogManager.getLogger(IndexSwapHelper.class);

    /** How many failing documents a failed copy of user content names before it stops listing. */
    private static final int MAX_REPORTED_FAILURES = 5;

    private IndexSwapHelper() {
        // utility class
    }

    /**
     * Inspects the cluster state to determine which physical index ({alias}-a or {alias}-b) the alias
     * currently points to, and returns the <b>other</b> suffix as the shadow target.
     *
     * @param client The OpenSearch client.
     * @param aliasName The public alias name (e.g., {@code "wazuh-threatintel-rules"}).
     * @return The shadow physical index name (e.g., {@code "wazuh-threatintel-rules-b"}).
     * @throws IllegalStateException If the alias does not resolve to a recognized {@code -a} / {@code
     *     -b} physical index.
     */
    public static String resolveShadowName(Client client, String aliasName) {
        String[] concreteIndices =
                client.admin().indices().prepareGetIndex().setIndices(aliasName).get().getIndices();

        if (concreteIndices.length != 1) {
            throw new IllegalStateException(
                    "Alias ["
                            + aliasName
                            + "] resolves to "
                            + concreteIndices.length
                            + " indices; expected exactly 1.");
        }

        String current = concreteIndices[0];
        if (current.endsWith(ContentIndex.SUFFIX_A)) {
            return aliasName + ContentIndex.SUFFIX_B;
        } else if (current.endsWith(ContentIndex.SUFFIX_B)) {
            return aliasName + ContentIndex.SUFFIX_A;
        } else {
            throw new IllegalStateException(
                    "Physical index ["
                            + current
                            + "] for alias ["
                            + aliasName
                            + "] does not end with '"
                            + ContentIndex.SUFFIX_A
                            + "' or '"
                            + ContentIndex.SUFFIX_B
                            + "'.");
        }
    }

    /**
     * Returns whether the slot the alias does not point at holds an index: the staging index of a
     * swap that has not switched yet, or the previous index of one that has.
     *
     * @param client The OpenSearch client.
     * @param aliasName The public alias name.
     * @return true if the other slot holds an index.
     * @throws IllegalStateException If the alias does not resolve to a recognized {@code -a} / {@code
     *     -b} physical index.
     */
    public static boolean shadowIndexExists(Client client, String aliasName) {
        String shadowPhysical = resolveShadowName(client, aliasName);
        return client.admin().indices().prepareExists(shadowPhysical).get().isExists();
    }

    /**
     * Returns the current live physical index name that the alias points to.
     *
     * @param client The OpenSearch client.
     * @param aliasName The public alias name.
     * @return The live physical index name.
     */
    public static String resolveLivePhysicalName(Client client, String aliasName) {
        String[] concreteIndices =
                client.admin().indices().prepareGetIndex().setIndices(aliasName).get().getIndices();

        if (concreteIndices.length != 1) {
            throw new IllegalStateException(
                    "Alias ["
                            + aliasName
                            + "] resolves to "
                            + concreteIndices.length
                            + " indices; expected exactly 1.");
        }
        return concreteIndices[0];
    }

    /**
     * Creates hidden shadow physical indices for all entries in the mappings map. Returns a map of
     * type → {@link ContentIndex} targeting the shadow physical names.
     *
     * @param client The OpenSearch client.
     * @param mappings A map of type identifier to classpath mapping resource path.
     * @param typeToAlias A function that converts a type identifier to the public alias name (e.g.,
     *     {@code "rule" → "wazuh-threatintel-rules"}).
     * @return A map of type → shadow ContentIndex instances.
     * @throws Exception If any shadow index creation fails.
     */
    public static Map<String, ContentIndex> createShadowIndices(
            Client client, Map<String, String> mappings, Function<String, String> typeToAlias)
            throws Exception {
        Map<String, ContentIndex> shadowMap = new HashMap<>();
        for (Map.Entry<String, String> entry : mappings.entrySet()) {
            String type = entry.getKey();
            String mappingsPath = entry.getValue();
            String aliasName = typeToAlias.apply(type);
            String shadowPhysical = resolveShadowName(client, aliasName);

            // The alias does not point at the staging slot, so anything there is a leftover, e.g. of a
            // swap interrupted midway, and would make the creation below fail.
            if (client.admin().indices().prepareExists(shadowPhysical).get().isExists()) {
                log.warn(Constants.W_LOG_STALE_SHADOW_INDEX_DELETED, shadowPhysical, aliasName);
                client.admin().indices().prepareDelete(shadowPhysical).get();
            }

            ContentIndex shadowIndex = new ContentIndex(client, aliasName, shadowPhysical, mappingsPath);
            CreateIndexResponse response = shadowIndex.createShadowIndex();
            if (response == null || !response.isAcknowledged()) {
                throw new IllegalStateException(
                        "Shadow index creation for [" + shadowPhysical + "] was not acknowledged");
            }
            shadowMap.put(type, shadowIndex);
            log.debug(Constants.D_LOG_SHADOW_INDEX_CREATED_FOR_ALIAS, shadowPhysical, aliasName);
        }
        return shadowMap;
    }

    /**
     * Reindexes user-edited content (documents where {@code space.name != "standard"}) from the live
     * physical indices to the shadow physical indices. This preserves draft, test, and custom space
     * content across the swap. A reindex that does not copy every document (a document rejected by
     * the shadow mapping, a search failure on the live index, or a timeout) fails the call: the live
     * index is deleted after the swap, so a document left behind would be lost with it.
     *
     * @param client The OpenSearch client.
     * @param liveToShadow A map of live physical index name → shadow physical index name.
     * @param timeoutSeconds The timeout for each reindex operation.
     * @throws IllegalStateException If a reindex reports failures or times out.
     */
    public static void reindexUserContent(
            Client client, Map<String, String> liveToShadow, long timeoutSeconds) {
        for (Map.Entry<String, String> entry : liveToShadow.entrySet()) {
            String livePhysical = entry.getKey();
            String shadowPhysical = entry.getValue();

            log.debug(Constants.D_LOG_REINDEX_USER_CONTENT_START, livePhysical, shadowPhysical);

            BulkByScrollResponse response;
            try {
                response =
                        new ReindexRequestBuilder(client, ReindexAction.INSTANCE)
                                .source(livePhysical)
                                .destination(shadowPhysical)
                                // This also carries the user-overrides registry document across the
                                // swap: it has no space.name, so it satisfies this must_not and lands
                                // in the new physical index alongside the user's own spaces.
                                .filter(
                                        QueryBuilders.boolQuery()
                                                .mustNot(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, "standard")))
                                .refresh(true)
                                .get(TimeValue.timeValueSeconds(timeoutSeconds));
            } catch (OpenSearchTimeoutException e) {
                // The wait ends here, not the reindex: it is still running on the node. Without this
                // the swap fails with a bare "Timeout waiting for task." that names no index and does
                // not say what timed out or what the deadline was.
                throw new IllegalStateException(
                        "copying user content from ["
                                + livePhysical
                                + "] to ["
                                + shadowPhysical
                                + "] did not finish within "
                                + timeoutSeconds
                                + "s (plugins.content_manager.client.timeout); the reindex may still be"
                                + " running on this node",
                        e);
            }
            checkReindexResponse(response, livePhysical, shadowPhysical);

            log.debug(Constants.D_LOG_REINDEX_USER_CONTENT_COMPLETE, livePhysical, shadowPhysical);
        }
    }

    /**
     * Fails when a reindex did not copy every document it matched.
     *
     * @param response The reindex response.
     * @param source The physical index the documents were copied from.
     * @param destination The physical index the documents were copied to.
     * @throws IllegalStateException If the reindex reports bulk or search failures, or timed out.
     */
    private static void checkReindexResponse(
            BulkByScrollResponse response, String source, String destination) {
        List<BulkItemResponse.Failure> bulkFailures = response.getBulkFailures();
        List<ScrollableHitSource.SearchFailure> searchFailures = response.getSearchFailures();
        if (bulkFailures.isEmpty() && searchFailures.isEmpty() && !response.isTimedOut()) {
            return;
        }
        // Every failure, not only the first: a copy that several documents block would otherwise
        // take one swap per document to clear, since the operator only learns of the next one once
        // the previous is fixed. Capped, because a reindex can fail by the thousand.
        StringBuilder reasons = new StringBuilder();
        int total = 0;
        if (!bulkFailures.isEmpty()) {
            total = bulkFailures.size();
            for (int i = 0; i < total && i < MAX_REPORTED_FAILURES; i++) {
                BulkItemResponse.Failure failure = bulkFailures.get(i);
                reasons
                        .append(i == 0 ? "" : "; ")
                        .append("document [")
                        .append(failure.getId())
                        .append("]: ")
                        .append(failure.getMessage());
            }
        } else if (!searchFailures.isEmpty()) {
            total = searchFailures.size();
            for (int i = 0; i < total && i < MAX_REPORTED_FAILURES; i++) {
                // getReason() is a bare Throwable, whose getMessage() can be null; the bulk branch
                // above renders the cause through Failure.getMessage(), which never comes back empty.
                reasons
                        .append(i == 0 ? "" : "; ")
                        .append(String.valueOf(searchFailures.get(i).getReason()));
            }
        }
        if (total > MAX_REPORTED_FAILURES) {
            reasons.append(" (and ").append(total - MAX_REPORTED_FAILURES).append(" more)");
        }
        throw new IllegalStateException(
                "copying user content from ["
                        + source
                        + "] to ["
                        + destination
                        + "] failed ("
                        + bulkFailures.size()
                        + " bulk failures, "
                        + searchFailures.size()
                        + " search failures, timed out: "
                        + response.isTimedOut()
                        + ")"
                        // Nothing to name when the only problem is the timed-out flag, which the
                        // counts above already report.
                        + (reasons.length() == 0 ? "" : ", failures: " + reasons));
    }

    /**
     * Refreshes the given physical indices, so that everything written to them is searchable. A shard
     * that fails to refresh fails the call: its content would be only partly searchable.
     *
     * @param client The OpenSearch client.
     * @param indexNames The physical index names to refresh.
     * @param timeoutSeconds The timeout for the refresh.
     * @throws Exception If the refresh fails or a shard does not refresh.
     */
    public static void refreshIndices(
            Client client, Collection<String> indexNames, long timeoutSeconds) throws Exception {
        RefreshResponse response =
                client
                        .admin()
                        .indices()
                        .prepareRefresh(indexNames.toArray(new String[0]))
                        .get(TimeValue.timeValueSeconds(timeoutSeconds));
        if (response.getFailedShards() > 0) {
            throw new IllegalStateException(
                    response.getFailedShards() + " shards of " + indexNames + " could not be refreshed");
        }
    }

    /**
     * Atomically swaps all aliases from old physical indices to new physical indices in a single
     * {@link IndicesAliasesRequest}. Before swapping, unhides non-hidden indices (all except CVEs).
     *
     * @param client The OpenSearch client.
     * @param aliasToNewPhysical Map of alias name → new physical index name.
     * @param aliasToOldPhysical Map of alias name → old physical index name.
     * @param timeoutSeconds Timeout for the operations.
     * @throws Exception If the swap fails.
     */
    public static void atomicSwap(
            Client client,
            Map<String, String> aliasToNewPhysical,
            Map<String, String> aliasToOldPhysical,
            long timeoutSeconds)
            throws Exception {

        // Unhide non-CVE shadow indices before the swap so they become visible.
        for (Map.Entry<String, String> entry : aliasToNewPhysical.entrySet()) {
            String aliasName = entry.getKey();
            String newPhysical = entry.getValue();

            if (!Constants.INDEX_CVES.equals(aliasName)) {
                UpdateSettingsRequest unhide =
                        new UpdateSettingsRequest()
                                .indices(newPhysical)
                                .settings(Settings.builder().put("index.hidden", false));
                client.admin().indices().updateSettings(unhide).get(timeoutSeconds, TimeUnit.SECONDS);
            }
        }

        // Build a single atomic alias swap request.
        IndicesAliasesRequest aliasRequest = new IndicesAliasesRequest();
        for (Map.Entry<String, String> entry : aliasToNewPhysical.entrySet()) {
            String aliasName = entry.getKey();
            String newPhysical = entry.getValue();
            String oldPhysical = aliasToOldPhysical.get(aliasName);

            aliasRequest.addAliasAction(
                    IndicesAliasesRequest.AliasActions.remove().index(oldPhysical).alias(aliasName));
            aliasRequest.addAliasAction(
                    IndicesAliasesRequest.AliasActions.add()
                            .index(newPhysical)
                            .alias(aliasName)
                            .writeIndex(true));
        }

        client.admin().indices().aliases(aliasRequest).get(timeoutSeconds, TimeUnit.SECONDS);
        log.debug(Constants.D_LOG_ALIAS_SWAP_COMPLETED, aliasToNewPhysical.size());
    }

    /**
     * Deletes the given physical indices. Used for cleanup: old indices after a successful swap, or
     * shadow indices after a failed swap.
     *
     * @param client The OpenSearch client.
     * @param indexNames The physical index names to delete.
     */
    public static void deleteIndices(Client client, Collection<String> indexNames) {
        for (String indexName : indexNames) {
            try {
                boolean exists = client.admin().indices().prepareExists(indexName).get().isExists();
                if (exists) {
                    client.admin().indices().prepareDelete(indexName).get();
                    log.debug(Constants.D_LOG_DELETED_PHYSICAL_INDEX, indexName);
                }
            } catch (Exception e) {
                log.warn(Constants.W_LOG_DELETE_PHYSICAL_INDEX_FAILED, indexName, e.getMessage());
            }
        }
    }
}
