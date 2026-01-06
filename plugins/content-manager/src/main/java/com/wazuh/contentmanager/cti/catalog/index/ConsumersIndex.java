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
package com.wazuh.contentmanager.cti.catalog.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;

/** Class to manage the Context index. */
public class ConsumersIndex {
    private static final Logger log = LogManager.getLogger(ConsumersIndex.class);

    /** The name of the Contexts index */
    public static final String INDEX_NAME = ".cti-consumers";

    /** Path of the index mapping file */
    private static final String MAPPING_PATH = "/mappings/consumers-mapping.json";

    private final Client client;
    private final PluginSettings pluginSettings;

    /**
     * Constructor.
     *
     * @param client OpenSearch client used for indexing and search operations.
     */
    public ConsumersIndex(Client client) {
        this.client = client;
        this.pluginSettings = PluginSettings.getInstance();
    }

    /**
     * Indexes a local consumer object into the cluster.
     *
     * @param consumer The {@link LocalConsumer} object containing the data to be indexed.
     * @return The {@link IndexResponse} indicating the result of the operation.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting for the
     *     response.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws IOException If there is an error serializing the consumer to XContent.
     * @throws RuntimeException If the target index is not currently ready or available.
     */
    public IndexResponse setConsumer(LocalConsumer consumer)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        // Avoid faulty requests if the cluster is unstable.
        if (!ClusterInfo.indexStatusCheck(this.client, INDEX_NAME)) {
            throw new RuntimeException("Index not ready");
        }
        // Composed ID
        String id = String.format(Locale.ROOT, "%s_%s", consumer.getContext(), consumer.getName());
        IndexRequest request =
                new IndexRequest().index(INDEX_NAME).id(id).source(consumer.toXContent());

        return this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Retrieves a consumer document from the index by its composite identifier.
     *
     * @param context The context identifier of the consumer.
     * @param consumer The name identifier of the consumer.
     * @return A {@link GetResponse} containing the document source and metadata.
     * @throws ExecutionException If the client failed to execute the request.
     * @throws InterruptedException If the current thread was interrupted while waiting for the
     *     response.
     * @throws TimeoutException If the operation exceeded the configured client timeout.
     * @throws RuntimeException If the target index is not currently ready or available.
     */
    public GetResponse getConsumer(String context, String consumer)
            throws ExecutionException, InterruptedException, TimeoutException {
        // Avoid faulty requests if the cluster is unstable.
        if (!ClusterInfo.indexStatusCheck(this.client, INDEX_NAME)) {
            throw new RuntimeException("Index not ready");
        }
        // Composed ID
        String id = String.format(Locale.ROOT, "%s_%s", context, consumer);
        GetRequest request = new GetRequest().index(INDEX_NAME).id(id).preference("_local");

        ActionFuture<GetResponse> future = this.client.get(request);

        return future.get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Checks whether the {@link ConsumersIndex#INDEX_NAME} index exists.
     *
     * @see ClusterInfo#indexExists(Client, String)
     * @return true if the index exists, false otherwise.
     */
    public boolean exists() {
        return ClusterInfo.indexExists(this.client, ConsumersIndex.INDEX_NAME);
    }

    /** Creates the {@link ConsumersIndex#INDEX_NAME} index. */
    public CreateIndexResponse createIndex()
            throws ExecutionException, InterruptedException, TimeoutException {
        Settings settings =
                Settings.builder().put("index.number_of_replicas", 0).put("hidden", true).build();

        String mappings;
        try {
            mappings = this.loadMappingFromResources();
        } catch (IOException e) {
            log.error("Could not read mappings for index [{}]", INDEX_NAME);
            return null;
        }

        CreateIndexRequest request =
                new CreateIndexRequest().index(INDEX_NAME).mapping(mappings).settings(settings);

        return this.client
                .admin()
                .indices()
                .create(request)
                .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Loads the index mapping from the 'resources' folder.
     *
     * @return the mapping as a JSON string.
     * @throws IOException if reading the resource fails.
     */
    protected String loadMappingFromResources() throws IOException {
        try (InputStream is = this.getClass().getResourceAsStream(MAPPING_PATH)) {
            if (is == null) {
                throw new java.io.FileNotFoundException("Mapping file not found: " + MAPPING_PATH);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
