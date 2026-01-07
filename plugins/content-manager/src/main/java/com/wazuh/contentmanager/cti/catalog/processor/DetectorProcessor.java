/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.processor;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.utils.CategoryFormatter;
import com.wazuh.securityanalytics.action.WIndexDetectorAction;
import com.wazuh.securityanalytics.action.WIndexDetectorRequest;

/**
 * Processes detector documents and creates/updates threat detectors in the security analytics
 * plugin.
 */
public class DetectorProcessor {
    private static final Logger log = LogManager.getLogger(DetectorProcessor.class);

    private final Client client;

    /**
     * Constructs a new DetectorProcessor.
     *
     * @param client The OpenSearch client.
     */
    public DetectorProcessor(Client client) {
        this.client = client;
    }

    /**
     * Processes integrations and creates/updates corresponding detectors.
     *
     * @param integrations Map of integration names to their rule IDs.
     * @param indexName The index containing integration documents.
     */
    public void process(Map<String, List<String>> integrations, String indexName) {
        log.info("Creating detectors for integrations: {}", integrations.keySet());
        try {
            if (!this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                log.warn("Integration index [{}] does not exist, skipping detector sync.", indexName);
                return;
            }

            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.matchAllQuery());
            searchSourceBuilder.size(10000);
            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();
            for (SearchHit hit : searchResponse.getHits().getHits()) {
                this.processHit(hit);
            }
        } catch (Exception e) {
            log.error("Error reading integrations from index [{}]: {}", indexName, e.getMessage());
        }
    }

    /**
     * Processes a single search hit and creates/updates the corresponding detector.
     *
     * @param hit The search hit containing integration data.
     */
    private void processHit(SearchHit hit) {
        try {
            JsonObject source = JsonParser.parseString(hit.getSourceAsString()).getAsJsonObject();
            if (source.has("document")) {
                JsonObject doc = source.getAsJsonObject("document");
                String name = doc.has("title") ? doc.get("title").getAsString() : "";
                String category = CategoryFormatter.format(doc, true);
                List<String> rules = new ArrayList<>();
                if (doc.has("rules")) {
                    doc.get("rules").getAsJsonArray().forEach(item -> rules.add(item.getAsString()));
                }

                WIndexDetectorRequest request =
                        new WIndexDetectorRequest(
                                hit.getId(), name, category, rules, WriteRequest.RefreshPolicy.IMMEDIATE);
                this.client.execute(WIndexDetectorAction.INSTANCE, request).get(1, TimeUnit.SECONDS);
                log.info("Detector [{}] synced successfully.", name);
            }
        } catch (JsonSyntaxException | InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Failed to sync Threat Detector from hit [{}]: {}", hit.getId(), e.getMessage());
        }
    }
}
