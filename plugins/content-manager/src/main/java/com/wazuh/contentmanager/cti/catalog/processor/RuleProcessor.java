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
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.search.SearchHit;
import org.opensearch.transport.client.Client;

import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.securityanalytics.action.WIndexRuleAction;
import com.wazuh.securityanalytics.action.WIndexRuleRequest;
import com.wazuh.securityanalytics.action.WIndexRuleResponse;

import static org.opensearch.rest.RestRequest.Method.POST;

/** Processes rule documents from a CTI index and syncs them to the security analytics plugin. */
public class RuleProcessor extends AbstractProcessor {

    private static final String CATEGORY = "category";

    /**
     * Constructs a new RuleProcessor.
     *
     * @param client The OpenSearch client.
     */
    public RuleProcessor(Client client) {
        super(client);
    }

    @Override
    protected String getProcessorName() {
        return "Rule";
    }

    /**
     * Processes rule documents and creates/updates them in the security analytics plugin.
     *
     * @param indexName The index containing rule documents.
     */
    public void process(String indexName) {
        if (!indexExists(indexName)) {
            log.warn("Rule index [{}] does not exist, skipping rule sync.", indexName);
            return;
        }

        resetCounters();
        SearchResponse searchResponse = searchAll(indexName);
        long totalHits = searchResponse.getHits().getTotalHits().value();
        int hitsReturned = searchResponse.getHits().getHits().length;
        log.info(
                "Rule index [{}] contains {} total documents, retrieved {} for processing",
                indexName,
                totalHits,
                hitsReturned);

        for (SearchHit hit : searchResponse.getHits().getHits()) {
            processHit(hit);
        }

        log.info(
                "Rule processing completed: {} succeeded, {} failed, {} skipped (total hits: {})",
                successCount,
                failCount,
                skippedCount,
                totalHits);
    }

    private void processHit(SearchHit hit) {
        JsonObject source = parseHit(hit);
        if (source == null) {
            return;
        }

        JsonObject doc = extractDocument(source, hit.getId());
        if (doc == null) {
            return;
        }

        if (!doc.has("id")) {
            log.warn("Rule document missing 'id' field, skipping: {}", hit.getId());
            skippedCount++;
            return;
        }

        String id = doc.get("id").getAsString();
        String product = determineProduct(doc);

        try {
            WIndexRuleRequest ruleRequest =
                    new WIndexRuleRequest(
                            id, WriteRequest.RefreshPolicy.IMMEDIATE, product, POST, doc.toString(), false);

            WIndexRuleResponse response =
                    this.client
                            .execute(WIndexRuleAction.INSTANCE, ruleRequest)
                            .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
            log.debug("Rule [{}] synced successfully. Response ID: {}", id, response.getId());
            successCount++;
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.warn("Failed to sync rule [{}]: {}", id, e.getMessage());
            failCount++;
        }
    }

    private String determineProduct(JsonObject doc) {
        String product = "linux"; // Default
        if (doc.has("logsource")) {
            JsonObject logsource = doc.getAsJsonObject("logsource");
            if (logsource.has("product")) {
                product = logsource.get("product").getAsString();
            } else if (logsource.has(CATEGORY)) {
                product = logsource.get(CATEGORY).getAsString();
            }
        }
        return product;
    }
}
