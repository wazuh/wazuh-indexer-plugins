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
public class IntegrationProcessor extends AbstractProcessor {

    /**
     * Constructs a new IntegrationProcessor.
     *
     * @param client The OpenSearch client.
     */
    public IntegrationProcessor(Client client) {
        super(client);
    }

    @Override
    protected String getProcessorName() {
        return "Integration";
    }

    /**
     * Processes integration documents and creates/updates them in the security analytics plugin.
     *
     * @param indexName The index containing integration documents.
     * @return A map of integration names to their associated rule IDs.
     */
    public Map<String, List<String>> process(String indexName) {
        Map<String, List<String>> integrations = new HashMap<>();

        if (!indexExists(indexName)) {
            log.warn("Integration index [{}] does not exist, skipping integration sync.", indexName);
            return integrations;
        }

        resetCounters();
        SearchResponse searchResponse = searchAll(indexName);

        for (SearchHit hit : searchResponse.getHits().getHits()) {
            processHit(hit, integrations);
        }

        log.info("Integration processing completed: {} succeeded, {} failed", successCount, failCount);
        return integrations;
    }

    private void processHit(SearchHit hit, Map<String, List<String>> integrations) {
        JsonObject source = parseHit(hit);
        if (source == null) {
            return;
        }

        JsonObject doc = extractDocument(source, hit.getId());
        if (doc == null) {
            return;
        }

        String id = doc.get("id").getAsString();
        String name = doc.has("title") ? doc.get("title").getAsString() : "";
        String description = doc.has("description") ? doc.get("description").getAsString() : "";
        String category = CategoryFormatter.format(doc, false);

        List<String> rules = new ArrayList<>();
        if (doc.has("rules")) {
            doc.get("rules").getAsJsonArray().forEach(item -> rules.add(item.getAsString()));
        }

        if (rules.isEmpty()) {
            skippedCount++;
            return;
        }

        try {
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
                            .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
            log.debug("Integration [{}] synced successfully. Response ID: {}", id, response.getId());
            integrations.put(name, rules);
            successCount++;
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.warn("Failed to sync integration [{}]: {}", id, e.getMessage());
            failCount++;
        }
    }
}
