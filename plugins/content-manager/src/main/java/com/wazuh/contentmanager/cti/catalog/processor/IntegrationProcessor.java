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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.utils.CategoryFormatter;
import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import com.wazuh.securityanalytics.action.WIndexIntegrationRequest;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;
import com.wazuh.securityanalytics.model.Integration;

import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * Processes integration documents from a CTI index and syncs them to the security analytics plugin.
 */
public class IntegrationProcessor {
    private static final Logger log = LogManager.getLogger(IntegrationProcessor.class);

    private final Client client;

    /**
     * Constructs a new IntegrationProcessor.
     *
     * @param client The OpenSearch client.
     */
    public IntegrationProcessor(Client client) {
        this.client = client;
    }

    /**
     * Processes integration documents and creates/updates them in the security analytics plugin.
     *
     * @param indexName The index containing integration documents.
     * @return A map of integration names to their associated rule IDs.
     */
    public Map<String, List<String>> process(String indexName) {
        Map<String, List<String>> integrations = new HashMap<>();
        try {
            if (!this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                log.warn("Integration index [{}] does not exist, skipping integration sync.", indexName);
                return integrations;
            }

            SearchRequest searchRequest = new SearchRequest(indexName);
            SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
            searchSourceBuilder.query(QueryBuilders.matchAllQuery());
            searchSourceBuilder.size(10000);
            searchRequest.source(searchSourceBuilder);

            SearchResponse searchResponse = this.client.search(searchRequest).actionGet();

            for (SearchHit hit : searchResponse.getHits().getHits()) {
                try {
                    JsonObject source = JsonParser.parseString(hit.getSourceAsString()).getAsJsonObject();
                    if (source.has("document")) {
                        JsonObject doc = source.getAsJsonObject("document");
                        String id = doc.get("id").getAsString();
                        String name = doc.has("title") ? doc.get("title").getAsString() : "";
                        String description = doc.has("description") ? doc.get("description").getAsString() : "";
                        String category = CategoryFormatter.format(doc, false);
                        List<String> rules = new ArrayList<>();
                        if (doc.has("rules")) {
                            doc.get("rules").getAsJsonArray().forEach(item -> rules.add(item.getAsString()));
                        }
                        if (rules.isEmpty()) {
                            continue;
                        }
                        WIndexIntegrationRequest request =
                                new WIndexIntegrationRequest(
                                        id,
                                        WriteRequest.RefreshPolicy.IMMEDIATE,
                                        POST,
                                        new Integration(
                                                id, null, name, description, category, "Sigma", rules, new HashMap<>()));

                        WIndexIntegrationResponse response =
                                this.client
                                        .execute(WIndexIntegrationAction.INSTANCE, request)
                                        .get(1, TimeUnit.SECONDS);
                        log.info("Integration [{}] synced successfully. Response ID: {}", id, response.getId());
                        integrations.put(name, rules);
                    }
                } catch (JsonSyntaxException e) {
                    log.error(
                            "Failed to sync integration from hit [{}]: {} {}", hit.getId(), e.getMessage(), e);
                }
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Error processing integrations from index [{}]: {}", indexName, e.getMessage());
        }
        return integrations;
    }
}
