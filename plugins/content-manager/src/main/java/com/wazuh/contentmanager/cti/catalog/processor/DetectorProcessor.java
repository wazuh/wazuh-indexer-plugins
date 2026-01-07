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
public class DetectorProcessor extends AbstractProcessor {

    /**
     * Constructs a new DetectorProcessor.
     *
     * @param client The OpenSearch client.
     */
    public DetectorProcessor(Client client) {
        super(client);
    }

    @Override
    protected String getProcessorName() {
        return "Detector";
    }

    /**
     * Processes integrations and creates/updates corresponding detectors.
     *
     * @param integrations Map of integration names to their rule IDs.
     * @param indexName The index containing integration documents.
     */
    public void process(Map<String, List<String>> integrations, String indexName) {
        log.info("Creating detectors for integrations: {}", integrations.keySet());

        if (!indexExists(indexName)) {
            log.warn("Integration index [{}] does not exist, skipping detector sync.", indexName);
            return;
        }

        resetCounters();
        SearchResponse searchResponse = searchAll(indexName);

        for (SearchHit hit : searchResponse.getHits().getHits()) {
            processHit(hit);
        }

        log.info("Detector processing completed: {} succeeded, {} failed", successCount, failCount);
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

        String name = doc.has("title") ? doc.get("title").getAsString() : "";
        String category = CategoryFormatter.format(doc, true);

        List<String> rules = new ArrayList<>();
        if (doc.has("rules")) {
            doc.get("rules").getAsJsonArray().forEach(item -> rules.add(item.getAsString()));
        }

        try {
            WIndexDetectorRequest request =
                    new WIndexDetectorRequest(
                            hit.getId(), name, category, rules, WriteRequest.RefreshPolicy.IMMEDIATE);
            this.client
                    .execute(WIndexDetectorAction.INSTANCE, request)
                    .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
            log.debug("Detector [{}] synced successfully.", name);
            successCount++;
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.warn("Failed to sync Threat Detector [{}]: {}", name, e.getMessage());
            failCount++;
        }
    }
}
