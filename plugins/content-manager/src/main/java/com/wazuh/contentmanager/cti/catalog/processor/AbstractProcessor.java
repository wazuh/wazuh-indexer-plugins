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
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Abstract base class for CTI document processors. Provides common functionality for searching
 * indices, parsing search hits, and tracking processing statistics. Concrete implementations handle
 * specific document types such as rules, integrations, and detectors.
 *
 * <p>This class provides shared utilities including index existence checks, bulk search operations,
 * JSON parsing, and processing counters. Subclasses implement the specific processing logic for
 * their document type while leveraging these common capabilities.
 *
 * <p>Processing counters track success, failure, and skipped counts across each processing run,
 * enabling detailed logging and monitoring of synchronization operations.
 */
public abstract class AbstractProcessor {

    /** Logger instance for the concrete processor class. Initialized with the subclass type. */
    protected final Logger log;

    /** OpenSearch client for executing index operations and search requests. */
    protected final Client client;

    /** Plugin settings providing configuration values such as client timeouts. */
    protected final PluginSettings pluginSettings;

    /** Counter tracking the number of documents successfully processed in the current run. */
    protected int successCount;

    /** Counter tracking the number of documents that failed processing in the current run. */
    protected int failCount;

    /** Counter tracking documents skipped due to missing required fields in the current run. */
    protected int skippedCount;

    /**
     * Constructs a new AbstractProcessor.
     *
     * @param client The OpenSearch client.
     */
    protected AbstractProcessor(Client client) {
        this.client = client;
        this.pluginSettings = PluginSettings.getInstance();
        this.log = LogManager.getLogger(getClass());
    }

    /**
     * Checks if the specified index exists.
     *
     * @param indexName The name of the index to check.
     * @return true if the index exists, false otherwise.
     */
    protected boolean indexExists(String indexName) {
        return this.client.admin().indices().prepareExists(indexName).get().isExists();
    }

    /**
     * Executes a search request to retrieve all documents from the specified index.
     *
     * @param indexName The index to search.
     * @return The search response containing matching documents.
     */
    protected SearchResponse searchAll(String indexName) {
        SearchRequest searchRequest = new SearchRequest(indexName);
        SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
        searchSourceBuilder.query(QueryBuilders.matchAllQuery());
        searchSourceBuilder.size(10000);
        searchRequest.source(searchSourceBuilder);
        return this.client.search(searchRequest).actionGet();
    }

    /**
     * Resets the processing counters to zero. Should be called at the start of each processing run.
     */
    protected void resetCounters() {
        this.successCount = 0;
        this.failCount = 0;
        this.skippedCount = 0;
    }

    /**
     * Extracts and parses the JSON document from a search hit.
     *
     * @param hit The search hit to process.
     * @return The parsed JsonObject, or null if parsing fails.
     */
    protected JsonObject parseHit(SearchHit hit) {
        try {
            return JsonParser.parseString(hit.getSourceAsString()).getAsJsonObject();
        } catch (JsonSyntaxException e) {
            log.error("Failed to parse JSON from hit [{}]: {}", hit.getId(), e.getMessage());
            this.failCount++;
            return null;
        }
    }

    /**
     * Extracts the "document" field from a parsed source object.
     *
     * @param source The parsed source JsonObject.
     * @param hitId The hit ID for logging purposes.
     * @return The document JsonObject, or null if not present.
     */
    protected JsonObject extractDocument(JsonObject source, String hitId) {
        if (!source.has("document")) {
            log.warn("Hit [{}] missing 'document' field, skipping", hitId);
            this.skippedCount++;
            return null;
        }
        return source.getAsJsonObject("document");
    }

    /**
     * Returns the name of the processor for logging purposes.
     *
     * @return The processor name.
     */
    protected abstract String getProcessorName();
}
