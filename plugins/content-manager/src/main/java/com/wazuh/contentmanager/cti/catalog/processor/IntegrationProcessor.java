package com.wazuh.contentmanager.cti.catalog.processor;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.index.query.QueryBuilders;
import static org.opensearch.rest.RestRequest.Method.POST;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import com.google.gson.JsonSyntaxException;
import com.wazuh.contentmanager.cti.catalog.utils.CategoryFormatter;
import com.wazuh.securityanalytics.action.WIndexIntegrationAction;
import com.wazuh.securityanalytics.action.WIndexIntegrationRequest;
import com.wazuh.securityanalytics.action.WIndexIntegrationResponse;
import com.wazuh.securityanalytics.model.Integration;

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
                        WIndexIntegrationRequest request = new WIndexIntegrationRequest(
                            id,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            POST,
                            new Integration(
                                id,
                                null,
                                name,
                                description,
                                category,
                                "Sigma",
                                rules,
                                new HashMap<>()
                            )
                        );

                        WIndexIntegrationResponse response = this.client.execute(WIndexIntegrationAction.INSTANCE, request).get(1, TimeUnit.SECONDS);
                        log.info("Integration [{}] synced successfully. Response ID: {}", id, response.getId());
                        integrations.put(name, rules);
                    }
                } catch (JsonSyntaxException e) {
                    log.error("Failed to sync integration from hit [{}]: {} {}", hit.getId(), e.getMessage(), e);
                }
            }
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Error processing integrations from index [{}]: {}", indexName, e.getMessage());
        }
        return integrations;
    }
}