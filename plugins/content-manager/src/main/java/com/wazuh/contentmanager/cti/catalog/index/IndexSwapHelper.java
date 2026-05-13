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
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.index.reindex.ReindexRequestBuilder;
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

            ContentIndex shadowIndex = new ContentIndex(client, aliasName, shadowPhysical, mappingsPath);
            shadowIndex.createShadowIndex();
            shadowMap.put(type, shadowIndex);
            log.info("Created shadow index [{}] for alias [{}]", shadowPhysical, aliasName);
        }
        return shadowMap;
    }

    /**
     * Reindexes user-edited content (documents where {@code space.name != "standard"}) from the live
     * physical indices to the shadow physical indices. This preserves draft, test, and custom space
     * content across the swap.
     *
     * @param client The OpenSearch client.
     * @param liveToShadow A map of live physical index name → shadow physical index name.
     * @param timeoutSeconds The timeout for each reindex operation.
     */
    public static void reindexUserContent(
            Client client, Map<String, String> liveToShadow, long timeoutSeconds) {
        for (Map.Entry<String, String> entry : liveToShadow.entrySet()) {
            String livePhysical = entry.getKey();
            String shadowPhysical = entry.getValue();

            log.info("Reindexing user content from [{}] to [{}]", livePhysical, shadowPhysical);

            new ReindexRequestBuilder(client, ReindexAction.INSTANCE)
                    .source(livePhysical)
                    .destination(shadowPhysical)
                    .filter(
                            QueryBuilders.boolQuery()
                                    .mustNot(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, "standard")))
                    .refresh(true)
                    .get();

            log.info("User content reindex from [{}] to [{}] completed", livePhysical, shadowPhysical);
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
        log.info("Atomic alias swap completed for {} aliases", aliasToNewPhysical.size());
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
                    log.info("Deleted physical index [{}]", indexName);
                }
            } catch (Exception e) {
                log.warn("Failed to delete physical index [{}]: {}", indexName, e.getMessage());
            }
        }
    }
}
