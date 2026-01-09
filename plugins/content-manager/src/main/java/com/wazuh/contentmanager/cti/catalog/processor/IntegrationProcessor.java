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
 * Processes integration documents from the indices and synchronizes them to the security analytics
 * plugin. Integrations define collections of related rules that work together for specific use
 * cases or data sources. This processor extracts integration metadata and associated rule lists,
 * then creates or updates the corresponding integration definitions.
 *
 * <p>Each integration document contains a title, description, category, and list of rule IDs. The
 * processor builds a mapping of integration names to their rule lists, which is returned for use by
 * downstream processors such as the DetectorProcessor.
 *
 * <p>Integrations without any associated rules are skipped during processing. The processor tracks
 * success, failure, and skip counts for monitoring and logging purposes.
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

    /**
     * Processes all integration documents from the specified index and synchronizes them to the
     * security analytics plugin. Each integration is extracted, validated, and indexed using the
     * WIndexIntegrationAction.
     *
     * <p>The method builds and returns a map of integration names to their associated rule ID lists.
     * This map is typically used by downstream processors such as DetectorProcessor to create
     * corresponding detectors.
     *
     * @param indexName The name of the index containing integration documents to process.
     * @return A map where keys are integration names and values are lists of associated rule IDs.
     *     Returns an empty map if the index does not exist.
     */
    public Map<String, List<String>> process(String indexName) {
        Map<String, List<String>> integrations = new HashMap<>();

        if (!this.indexExists(indexName)) {
            this.log.warn("Integration index [{}] does not exist, skipping integration sync.", indexName);
            return integrations;
        }

        this.resetCounters();
        SearchResponse searchResponse = this.searchAll(indexName);

        for (SearchHit hit : searchResponse.getHits().getHits()) {
            this.processHit(hit, integrations);
        }

        this.log.info(
                "Integration processing completed: {} succeeded, {} failed",
                this.successCount,
                this.failCount);
        return integrations;
    }

    /**
     * Processes a single search hit containing an integration document. Extracts integration metadata
     * and rule associations, then sends the integration to the security analytics plugin.
     *
     * @param hit The search hit containing the integration document to process.
     * @param integrations The map to populate with integration name to rule ID list mappings.
     */
    private void processHit(SearchHit hit, Map<String, List<String>> integrations) {
        JsonObject source = this.parseHit(hit);
        if (source == null) {
            return;
        }

        JsonObject doc = this.extractDocument(source, hit.getId());
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
            this.skippedCount++;
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
            this.log.debug("Integration [{}] synced successfully. Response ID: {}", id, response.getId());
            integrations.put(name, rules);
            this.successCount++;
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            this.log.warn("Failed to sync integration [{}]: {}", id, e.getMessage());
            this.failCount++;
        }
    }
}
