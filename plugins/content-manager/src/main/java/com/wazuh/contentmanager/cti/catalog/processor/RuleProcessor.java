package com.wazuh.contentmanager.cti.catalog.processor;

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
import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

/**
 * Processes rule documents from a CTI index and syncs them to the security analytics plugin.
 */
public class RuleProcessor {
    private static final Logger log = LogManager.getLogger(RuleProcessor.class);
    static final String CATEGORY = "category";

    private final Client client;

    public RuleProcessor(Client client) {
        this.client = client;
    }

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

                        WIndexRuleRequest ruleRequest = new WIndexRuleRequest(
                            id,
                            WriteRequest.RefreshPolicy.IMMEDIATE,
                            product,
                            POST,
                            doc.toString(),
                            false
                        );

                        WIndexRuleResponse response = this.client.execute(WIndexRuleAction.INSTANCE, ruleRequest).get(1, TimeUnit.SECONDS);
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