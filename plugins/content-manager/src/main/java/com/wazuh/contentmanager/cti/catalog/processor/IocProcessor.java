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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import com.wazuh.contentmanager.utils.Constants;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.SearchHit;
import org.opensearch.transport.client.Client;

/**
 * Processes IoC (Indicator of Compromise) documents from the indices. IoCs represent observable
 * artifacts such as IP addresses, domains, file hashes, or URLs that indicate potential security
 * threats. This processor extracts IoC data and processes them for threat intelligence purposes.
 *
 * <p>The processor tracks success, failure, and skip counts for monitoring and logging purposes.
 */
public class IocProcessor extends AbstractProcessor {

    /**
     * Constructs a new IocProcessor.
     *
     * @param client The OpenSearch client.
     */
    public IocProcessor(Client client) {
        super(client);
    }

    /**
     * Processes all IoC documents from the specified index. Each IoC is extracted and validated.
     *
     * @param indexName The name of the index containing IoC documents to process.
     */
    public void process(String indexName) {
        if (!this.indexExists(indexName)) {
            this.log.warn("IoC index [{}] does not exist, skipping IoC processing.", indexName);
            return;
        }

        this.resetCounters();
        SearchResponse searchResponse = this.searchAll(indexName);

        for (SearchHit hit : searchResponse.getHits().getHits()) {
            this.processHit(hit);
        }

        this.log.info(
                "IoC processing completed: {} succeeded, {} failed", this.successCount, this.failCount);
    }

    /**
     * Processes a single search hit containing an IoC document. Extracts IoC data for threat
     * intelligence purposes. Unlike integrations, IoC documents have a flat structure where {@code
     * id} and {@code enrichments} are at the root level, without a {@code document} wrapper.
     *
     * @param hit The search hit containing the IoC document to process.
     */
    private void processHit(SearchHit hit) {
        JsonObject source = this.parseHit(hit);
        if (source == null) {
            return;
        }

        if (!source.has(Constants.KEY_ID)) {
            this.log.warn("Hit [{}] missing 'id' field, skipping", hit.getId());
            this.skippedCount++;
            return;
        }
        String id = source.get(Constants.KEY_ID).getAsString();

        if (!source.has(Constants.KEY_ENRICHMENTS) || !source.get(Constants.KEY_ENRICHMENTS).isJsonArray()) {
            this.log.warn("IoC [{}] missing 'enrichments' array, skipping", id);
            this.skippedCount++;
            return;
        }
        JsonArray enrichments = source.getAsJsonArray(Constants.KEY_ENRICHMENTS);

        this.log.debug("IoC [{}] processed successfully with {} enrichments.", id, enrichments.size());
        this.successCount++;
    }
}
