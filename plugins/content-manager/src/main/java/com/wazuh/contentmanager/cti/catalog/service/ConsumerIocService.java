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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.CreatePitAction;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.search.DeletePitAction;
import org.opensearch.action.search.DeletePitRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.env.Environment;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.PointInTimeBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;
import org.opensearch.transport.client.Client;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Handles synchronization logic for the IOC consumer. Processes IOCs and handles post-sync
 * operations including per-type SHA-256 hash computation.
 */
public class ConsumerIocService extends AbstractConsumerService {
    private static final Logger log = LogManager.getLogger(ConsumerIocService.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final int SEARCH_PAGE_SIZE = 10_000;

    /** The unified context identifier. */
    private final String CONTEXT = PluginSettings.getInstance().getIocContext();

    /** The unified consumer name identifier. */
    private final String CONSUMER = PluginSettings.getInstance().getIocConsumer();

    /**
     * Constructs a new ConsumerIocService.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     */
    public ConsumerIocService(Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
    }

    @Override
    protected String getContext() {
        return this.CONTEXT;
    }

    @Override
    protected String getConsumer() {
        return this.CONSUMER;
    }

    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(Constants.KEY_IOCS, "/mappings/cti-ioc-mappings.json");
        return mappings;
    }

    @Override
    protected Map<String, String> getAliases() {
        // We use the alias names as the actual index names, so we do not create separate aliases.
        return Collections.emptyMap();
    }

    @Override
    public void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            this.refreshIndices(Constants.INDEX_IOCS);
            this.computeAndStoreTypeHashes();
        }
    }

    /**
     * Computes per-type SHA-256 checksums for all IOC documents and stores them as a summary
     * document. Uses PIT (Point-in-Time) with search_after for deterministic, paginated iteration
     * over potentially millions of documents.
     */
    private void computeAndStoreTypeHashes() {
        long keepaliveSeconds = PluginSettings.getInstance().getPitKeepalive();
        TimeValue keepalive = TimeValue.timeValueSeconds(keepaliveSeconds);

        CreatePitRequest createPitRequest =
                new CreatePitRequest(keepalive, false, Constants.INDEX_IOCS);
        CreatePitResponse pitResponse =
                this.client.execute(CreatePitAction.INSTANCE, createPitRequest).actionGet();
        String pitId = pitResponse.getId();

        try {
            ObjectNode hashDocument = MAPPER.createObjectNode();

            for (String type : Constants.IOC_TYPES) {
                String hash = this.computeHashForType(pitId, keepalive, type);
                ObjectNode typeNode = MAPPER.createObjectNode();
                ObjectNode typeHashNode = MAPPER.createObjectNode();
                typeHashNode.put(Constants.KEY_SHA256, hash);
                typeNode.set(Constants.KEY_HASH, typeHashNode);
                hashDocument.set(type, typeNode);
            }

            IndexRequest indexRequest =
                    new IndexRequest(Constants.INDEX_IOCS)
                            .id(Constants.IOC_TYPE_HASHES_ID)
                            .source(hashDocument.toString(), XContentType.JSON);
            this.client.index(indexRequest).actionGet();

            log.info("IOC type hashes stored successfully.");
        } catch (Exception e) {
            log.error("Failed to compute and store IOC type hashes: {}", e.getMessage(), e);
        } finally {
            DeletePitRequest deletePitRequest = new DeletePitRequest(pitId);
            this.client.execute(DeletePitAction.INSTANCE, deletePitRequest).actionGet();
        }
    }

    /**
     * Computes the SHA-256 hash for all IOC documents of a given type using paginated PIT search.
     *
     * @param pitId The PIT identifier for consistent reads.
     * @param keepalive The PIT keepalive duration.
     * @param type The IOC type to filter by (e.g., "ip", "domain-name").
     * @return The SHA-256 hash of the concatenated per-document SHA-256 values, or hash of empty
     *     string if none found.
     */
    private String computeHashForType(String pitId, TimeValue keepalive, String type) {
        StringBuilder concatenated = new StringBuilder();
        Object[] searchAfter = null;

        while (true) {
            SearchSourceBuilder source =
                    new SearchSourceBuilder()
                            .query(QueryBuilders.termQuery(Constants.Q_DOCUMENT_TYPE, type))
                            .sort("_id", SortOrder.ASC)
                            .size(SEARCH_PAGE_SIZE)
                            .pointInTimeBuilder(new PointInTimeBuilder(pitId).setKeepAlive(keepalive));
            if (searchAfter != null) {
                source.searchAfter(searchAfter);
            }

            SearchRequest searchRequest = new SearchRequest();
            searchRequest.source(source);
            SearchResponse response = this.client.search(searchRequest).actionGet();
            SearchHit[] hits = response.getHits().getHits();
            if (hits.length == 0) {
                break;
            }

            for (SearchHit hit : hits) {
                Map<String, Object> sourceMap = hit.getSourceAsMap();
                @SuppressWarnings("unchecked")
                Map<String, Object> hashMap =
                        (Map<String, Object>) sourceMap.get(Constants.KEY_HASH);
                if (hashMap != null) {
                    Object sha256 = hashMap.get(Constants.KEY_SHA256);
                    if (sha256 != null) {
                        concatenated.append(sha256);
                    }
                }
            }
            searchAfter = hits[hits.length - 1].getSortValues();
        }

        return Resource.computeSha256(concatenated.toString());
    }
}
