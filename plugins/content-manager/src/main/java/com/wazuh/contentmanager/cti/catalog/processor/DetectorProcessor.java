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
package com.wazuh.contentmanager.cti.catalog.processor;

import com.google.gson.JsonObject;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.search.SearchHit;
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
 * Processes integration documents and creates threat detectors in the security analytics plugin.
 * Detectors are the operational components that apply rules to incoming log data to identify
 * potential security threats. This processor creates one detector per integration, associating it
 * with the integration's rules and category.
 *
 * <p>The processor reads integration documents from the CTI index to extract detector configuration
 * including name, category, and associated rule IDs. Each detector is created with an immediate
 * refresh policy to ensure it becomes active promptly.
 *
 * <p>Processing is performed synchronously with configurable timeouts. The processor tracks success
 * and failure counts for monitoring and logging purposes.
 */
public class DetectorProcessor extends AbstractProcessor {

    /**
     * Constructs a new DetectorProcessor.
     *
     * @param client The OpenSearch client.
     */
    public DetectorProcessor(Client client) {
        super(client);
    }

    /**
     * Creates or updates threat detectors for the provided integrations. Reads integration documents
     * from the index to extract detector configuration and creates corresponding detectors in the
     * security analytics plugin using WIndexDetectorAction.
     *
     * <p>The method first logs the integrations being processed, then retrieves all documents from
     * the index and processes each one to create a detector. Processing statistics are logged upon
     * completion.
     *
     * @param integrations Map of integration names to their associated rule ID lists. Used for
     *     logging which integrations are being processed.
     * @param indexName The name of the index containing integration documents with detector
     *     configuration.
     */
    public void process(Map<String, List<String>> integrations, String indexName) {
        this.log.info("Creating detectors for integrations: {}", integrations.keySet());

        if (!this.indexExists(indexName)) {
            this.log.warn("Integration index [{}] does not exist, skipping detector sync.", indexName);
            return;
        }

        this.resetCounters();
        SearchResponse searchResponse = this.searchAll(indexName);

        for (SearchHit hit : searchResponse.getHits().getHits()) {
            this.processHit(hit);
        }

        this.log.info(
                "Detector processing completed: {} succeeded, {} failed",
                this.successCount,
                this.failCount);
    }

    /**
     * Processes a single search hit containing an integration document and creates a corresponding
     * threat detector. Extracts detector name, category, and rule associations from the document.
     *
     * @param hit The search hit containing the integration document to process.
     */
    private void processHit(SearchHit hit) {
        JsonObject source = this.parseHit(hit);
        if (source == null) {
            return;
        }

        JsonObject doc = this.extractDocument(source, hit.getId());
        if (doc == null) {
            return;
        }

        String name = doc.has("title") ? doc.get("title").getAsString() : "";
        String category = CategoryFormatter.format(doc, true);

        List<String> rules = new ArrayList<>();
        if (doc.has("rules")) {
            doc.get("rules").getAsJsonArray().forEach(item -> rules.add(item.getAsString()));
        }

        if (!this.pluginSettings.getCreateDetectors()) {
            return;
        }

        try {
            WIndexDetectorRequest request =
                    new WIndexDetectorRequest(
                            hit.getId(), name, category, rules, WriteRequest.RefreshPolicy.IMMEDIATE);
            this.client
                    .execute(WIndexDetectorAction.INSTANCE, request)
                    .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
            this.log.debug("Detector [{}] synced successfully.", name);
            this.successCount++;
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            this.log.warn("Failed to sync Threat Detector [{}]: {}", name, e.getMessage());
            this.failCount++;
        }
    }
}
