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

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

import static org.opensearch.rest.RestRequest.Method.POST;

/** Processes rule documents from a CTI index and syncs them to the security analytics plugin. */
public class RuleProcessor {
    private static final Logger log = LogManager.getLogger(RuleProcessor.class);
    static final String CATEGORY = "category";

    private final Client client;

    /**
     * Constructs a new RuleProcessor.
     *
     * @param client The OpenSearch client.
     */
    public RuleProcessor(Client client) {
        this.client = client;
    }

    /**
     * Processes rule documents and creates/updates them in the security analytics plugin.
     *
     * @param indexName The index containing rule documents.
     */
    public void process(String indexName) {
        try {
            if (!this.client.admin().indices().prepareExists(indexName).get().isExists()) {
                log.warn("Rule index [{}] does not exist, skipping rule sync.", indexName);
                return;
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
                        // Extract the actual rule content
                        JsonObject doc = source.getAsJsonObject("document");

                        String id = doc.get("id").getAsString();

                        // Determine product for the rule request
                        String product = "linux"; // Default
                        if (doc.has("logsource")) {
                            JsonObject logsource = doc.getAsJsonObject("logsource");
                            if (logsource.has("product")) {
                                product = logsource.get("product").getAsString();
                            } else if (logsource.has(CATEGORY)) {
                                product = logsource.get(CATEGORY).getAsString();
                            }
                        }

                        WIndexRuleRequest ruleRequest =
                                new WIndexRuleRequest(
                                        id, WriteRequest.RefreshPolicy.IMMEDIATE, product, POST, doc.toString(), false);

                        WIndexRuleResponse response =
                                this.client
                                        .execute(WIndexRuleAction.INSTANCE, ruleRequest)
                                        .get(1, TimeUnit.SECONDS);
                        log.info("Rule [{}] synced successfully. Response ID: {}", id, response.getId());
                    }
                } catch (JsonSyntaxException e) {
                    log.error("Failed to sync rule from hit [{}]: {}", hit.getId(), e.getMessage());
                }
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Error processing rules from index [{}]: {}", indexName, e.getMessage());
        }
    }
}
