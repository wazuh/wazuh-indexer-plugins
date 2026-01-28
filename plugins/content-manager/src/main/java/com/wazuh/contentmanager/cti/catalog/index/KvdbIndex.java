/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.index;

import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;

/**
 * Manages the KVDB (Key-Value Database) index in the CTI system.
 *
 * <p>This class provides specialized operations for managing KVDB documents,
 * including creation, retrieval, and deletion. It wraps a {@link ContentIndex}
 * instance configured specifically for the KVDB index.
 */
public class KvdbIndex {
    private static final Logger log = LogManager.getLogger(KvdbIndex.class);

    /** The name of the KVDB index */
    public static final String INDEX_NAME = ".cti-kvdbs";

    /** Path to the KVDB index mapping file */
    private static final String MAPPING_PATH = "/mappings/cti-kvdbs-mappings.json";

    private final ContentIndex contentIndex;
    private final Client client;
    private final PluginSettings pluginSettings;

    /**
     * Constructs a new KvdbIndex manager.
     *
     * @param client The OpenSearch client used for indexing and search operations.
     */
    public KvdbIndex(Client client) {
        this.client = client;
        this.pluginSettings = PluginSettings.getInstance();
        this.contentIndex = new ContentIndex(client, INDEX_NAME, MAPPING_PATH);
    }

    /**
     * Returns the name of the KVDB index.
     *
     * @return The index name.
     */
    public String getIndexName() {
        return INDEX_NAME;
    }

    /**
     * Creates the KVDB index with the configured mappings and settings.
     *
     * @throws ExecutionException If the client execution fails.
     * @throws InterruptedException If the thread is interrupted while waiting.
     * @throws TimeoutException If the operation exceeds the client timeout setting.
     */
    public void createIndex() throws ExecutionException, InterruptedException, TimeoutException {
        this.contentIndex.createIndex();
        log.info("KVDB index [{}] created successfully", INDEX_NAME);
    }

    /**
     * Checks whether the KVDB index exists.
     *
     * @return true if the index exists, false otherwise.
     */
    public boolean exists() {
        return ClusterInfo.indexExists(this.client, INDEX_NAME);
    }

    /**
     * Checks if a KVDB document with the specified ID exists.
     *
     * @param id The ID of the KVDB document to check.
     * @return true if the document exists, false otherwise.
     */
    public boolean kvdbExists(String id) {
        return this.contentIndex.exists(id);
    }

    /**
     * Creates or updates a KVDB document.
     *
     * @param id The unique identifier for the KVDB document.
     * @param payload The JSON object representing the KVDB content.
     * @throws IOException If the indexing operation fails.
     */
    public void createKvdb(String id, JsonObject payload) throws IOException {
        this.contentIndex.create(id, payload);
        log.debug("KVDB document [{}] created/updated in index [{}]", id, INDEX_NAME);
    }

    /**
     * Retrieves a KVDB document by its ID.
     *
     * @param id The ID of the KVDB document to retrieve.
     * @return A {@link GetResponse} containing the document source and metadata.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws RuntimeException If the target index is not ready or available.
     */
    public GetResponse getKvdb(String id)
            throws ExecutionException, InterruptedException, TimeoutException {
        // Avoid faulty requests if the cluster is unstable
        if (!ClusterInfo.indexStatusCheck(this.client, INDEX_NAME)) {
            throw new RuntimeException("KVDB index not ready");
        }

        GetRequest request = new GetRequest().index(INDEX_NAME).id(id).preference("_local");

        return this.client.get(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Deletes a KVDB document by its ID asynchronously.
     *
     * @param id The ID of the KVDB document to delete.
     */
    public void deleteKvdb(String id) {
        this.contentIndex.delete(id);
        log.debug("Delete request sent for KVDB document [{}] in index [{}]", id, INDEX_NAME);
    }

    /**
     * Deletes a KVDB document by its ID synchronously.
     *
     * @param id The ID of the KVDB document to delete.
     * @return A {@link DeleteResponse} indicating the result of the operation.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws RuntimeException If the target index is not ready or available.
     */
    public DeleteResponse deleteKvdbSync(String id)
            throws ExecutionException, InterruptedException, TimeoutException {
        // Avoid faulty requests if the cluster is unstable
        if (!ClusterInfo.indexStatusCheck(this.client, INDEX_NAME)) {
            throw new RuntimeException("KVDB index not ready");
        }

        org.opensearch.action.delete.DeleteRequest request =
                new org.opensearch.action.delete.DeleteRequest(INDEX_NAME, id);

        return this.client.delete(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Searches for a KVDB document using a custom query.
     *
     * @param queryBuilder The query to execute.
     * @return A JsonObject representing the search results, or null if not found.
     */
    public JsonObject searchKvdb(org.opensearch.index.query.QueryBuilder queryBuilder) {
        return this.contentIndex.searchByQuery(queryBuilder);
    }

    /**
     * Clears all KVDB documents from the index.
     *
     * <p><b>Warning:</b> This operation deletes all documents in the KVDB index.
     */
    public void clearAll() {
        this.contentIndex.clear();
        log.info("All KVDB documents cleared from index [{}]", INDEX_NAME);
    }

    /**
     * Returns the underlying {@link ContentIndex} instance for advanced operations.
     *
     * @return The ContentIndex managing the KVDB index.
     */
    public ContentIndex getContentIndex() {
        return this.contentIndex;
    }
}
