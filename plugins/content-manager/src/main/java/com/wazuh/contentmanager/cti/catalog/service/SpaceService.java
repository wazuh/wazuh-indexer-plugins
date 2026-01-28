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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;

/** Service for retrieving resource information based on their Space. */
public class SpaceService {
    private static final Logger log = LogManager.getLogger(SpaceService.class);

    private final Client client;

    // Index Constants
    private static final String INDEX_POLICIES = ".cti-policies";
    private static final String INDEX_INTEGRATIONS = ".cti-integrations";
    private static final String INDEX_KVDBS = ".cti-kvdbs";
    private static final String INDEX_DECODERS = ".cti-decoders";
    private static final String INDEX_FILTERS = ".engine-filters";

    // Resource Types Keys
    public static final String KEY_POLICY = "policy";
    public static final String KEY_INTEGRATIONS = "integrations";
    public static final String KEY_KVDBS = "kvdbs";
    public static final String KEY_DECODERS = "decoders";
    public static final String KEY_FILTERS = "filters";

    // Mapping from Output Key -> Index Name
    private static final Map<String, String> RESOURCE_INDICES =
            Map.of(
                    KEY_POLICY, INDEX_POLICIES,
                    KEY_INTEGRATIONS, INDEX_INTEGRATIONS,
                    KEY_KVDBS, INDEX_KVDBS,
                    KEY_DECODERS, INDEX_DECODERS,
                    KEY_FILTERS, INDEX_FILTERS);

    public SpaceService(Client client) {
        this.client = client;
    }

    /**
     * Fetches all resources (ID and Hash) for a given space. Iterates over all managed resource types
     * and their corresponding indices.
     *
     * @param spaceName The space to filter by (e.g., "draft", "test")
     * @return A map where Key=ResourceType (e.g. "decoders") and Value=Map(ID -> Hash)
     */
    public Map<String, Map<String, String>> getSpaceResources(String spaceName) {
        Map<String, Map<String, String>> spaceResources = new HashMap<>();

        for (Map.Entry<String, String> entry : RESOURCE_INDICES.entrySet()) {
            String resourceType = entry.getKey();
            String indexName = entry.getValue();

            Map<String, String> items = new HashMap<>();

            try {
                // Check if index exists before querying
                if (this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                    SearchRequest searchRequest = new SearchRequest(indexName);
                    SearchSourceBuilder sourceBuilder = new SearchSourceBuilder();

                    // Filter by space
                    sourceBuilder.query(QueryBuilders.termQuery("space.name", spaceName));
                    sourceBuilder.fetchSource(new String[] {"hash.sha256"}, null);
                    sourceBuilder.size(10000);

                    searchRequest.source(sourceBuilder);
                    SearchResponse response = this.client.search(searchRequest).actionGet();

                    for (SearchHit hit : response.getHits().getHits()) {
                        String hash = HashCalculator.extractHash(hit.getSourceAsMap());
                        items.put(hit.getId(), hash);
                    }
                }
            } catch (Exception e) {
                log.warn(
                        "Failed to fetch [{}] from index [{}] for space [{}]: {}",
                        resourceType,
                        indexName,
                        spaceName,
                        e.getMessage());
            }

            spaceResources.put(resourceType, items);
        }

        return spaceResources;
    }
}
