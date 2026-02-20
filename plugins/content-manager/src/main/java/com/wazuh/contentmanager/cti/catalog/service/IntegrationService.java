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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Service for managing integration relationships with resources. Handles linking and unlinking
 * resources (rules, decoders, kvdbs) to/from integrations.
 */
public class IntegrationService {
    private static final Logger log = LogManager.getLogger(IntegrationService.class);
    private final Client client;
    private final ObjectMapper mapper;

    /**
     * Constructs an IntegrationService.
     *
     * @param client The OpenSearch client.
     */
    public IntegrationService(Client client) {
        this.client = client;
        this.mapper = new ObjectMapper();
    }

    /**
     * Links a resource to an integration by adding its ID to the specified list field.
     *
     * @param integrationId The ID of the integration to update.
     * @param resourceId The ID of the resource to link.
     * @param listKey The key of the list field in the integration document (e.g., "rules").
     * @throws IOException If the integration cannot be found or updated.
     */
    @SuppressWarnings("unchecked")
    public void linkResourceToIntegration(String integrationId, String resourceId, String listKey)
            throws IOException {
        GetResponse response =
                this.client.prepareGet(Constants.INDEX_INTEGRATIONS, integrationId).get();

        if (!response.isExists()) {
            throw new IOException("Integration [" + integrationId + "] not found.");
        }

        Map<String, Object> source = response.getSourceAsMap();
        Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);

        List<String> list = (List<String>) document.getOrDefault(listKey, new ArrayList<>());

        // Ensure list is mutable
        if (!(list instanceof ArrayList)) {
            list = new ArrayList<>(list);
        }

        if (!list.contains(resourceId)) {
            list.add(resourceId);
            document.put(listKey, list);
            this.updateIntegrationSource(response.getId(), document, source);
        }
    }

    /**
     * Unlinks a resource from all integrations that reference it.
     *
     * @param resourceId The ID of the resource to unlink.
     * @param listKey The key of the list field in the integration document (e.g., "rules").
     * @throws IOException If searching or updating the integration fails.
     */
    public void unlinkResourceFromIntegrations(String resourceId, String listKey) throws IOException {
        SearchRequest searchRequest = new SearchRequest(Constants.INDEX_INTEGRATIONS);
        BoolQueryBuilder query =
                QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery(Constants.KEY_DOCUMENT + "." + listKey, resourceId))
                        .filter(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, Space.DRAFT.toString()));
        searchRequest.source().query(query);

        try {
            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();
            for (SearchHit hit : searchResponse.getHits().getHits()) {
                Map<String, Object> source = hit.getSourceAsMap();
                @SuppressWarnings("unchecked")
                Map<String, Object> document = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);

                @SuppressWarnings("unchecked")
                List<String> list = (List<String>) document.get(listKey);

                if (list != null) {
                    List<String> updatedList = new ArrayList<>(list);
                    if (updatedList.remove(resourceId)) {
                        document.put(listKey, updatedList);
                        this.updateIntegrationSource(hit.getId(), document, source);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error unlinking resource [{}] from integrations: {}", resourceId, e.getMessage());
            throw new IOException("Failed to unlink resource from integrations: " + e.getMessage(), e);
        }
    }

    /**
     * Updates the integration document in the index with a recalculated hash.
     *
     * @param id Integration ID.
     * @param document The updated document content.
     * @param source The full source map including metadata.
     * @throws IOException If indexing fails.
     */
    public void updateIntegrationSource(
            String id, Map<String, Object> document, Map<String, Object> source) throws IOException {
        JsonNode documentNode = this.mapper.valueToTree(document);
        String newHash = Resource.computeSha256(documentNode.toString());

        Map<String, Object> hashMap = new HashMap<>();
        hashMap.put(Constants.KEY_SHA256, newHash);
        source.put(Constants.KEY_HASH, hashMap);
        source.put(Constants.KEY_DOCUMENT, document);

        this.client
                .index(
                        new IndexRequest(Constants.INDEX_INTEGRATIONS)
                                .id(id)
                                .source(source)
                                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE))
                .actionGet();
    }
}
