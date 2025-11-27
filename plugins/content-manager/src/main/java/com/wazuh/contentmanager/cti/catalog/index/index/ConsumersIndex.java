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
package com.wazuh.contentmanager.cti.catalog.index.index;

import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.transport.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.ToXContent;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.model.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;

/** Class to manage the Context index. */
// TODO remove unused methods: all but setConsumer(), getConsumer() and createIndex()
public class ConsumersIndex {
    private static final Logger log = LogManager.getLogger(ConsumersIndex.class);

    /** The name of the Contexts index */
    public static final String INDEX_NAME = ".cti-consumers";
    /** Path of the index mapping file */
    private static final String MAPPING_PATH = "/mappings/consumers-mapping.json";

    private final Client client;

    /**
     * This instance of ConsumerInfo comprehends the internal state of this class. The ContextIndex
     * class is responsible for maintaining its internal state update at all times.
     */
    private ConsumerInfo consumerInfo;

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
     * Index CTI API consumer information.
     *
     * @param consumerInfo Model containing information parsed from the CTI API.
     * @return the IndexResponse from the indexing operation, or null.
     */
    public boolean index(ConsumerInfo consumerInfo) {
        try {
            IndexRequest indexRequest =
                    new IndexRequest()
                            .index(ConsumersIndex.INDEX_NAME)
                            .source(
                                    consumerInfo.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .id(consumerInfo.getContext());

            IndexResponse indexResponse =
                    this.client
                            .index(indexRequest)
                            .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
            if (indexResponse.getResult() == DocWriteResponse.Result.CREATED
                    || indexResponse.getResult() == DocWriteResponse.Result.UPDATED) {
                // Update consumer info (internal state).
                this.consumerInfo = consumerInfo;
                return true;
            }
        } catch (IOException e) {
            log.error("Failed to create JSON content builder: {}", e.getMessage());
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Failed to index Consumer [{}] information due to: {}",
                    consumerInfo.getContext(),
                    e.getMessage());
        }
        return false;
    }

    public IndexResponse setConsumer(LocalConsumer consumer) throws ExecutionException, InterruptedException, TimeoutException, IOException {
        // Avoid faulty requests if the cluster is unstable.
        if (!ClusterInfo.indexStatusCheck(this.client, INDEX_NAME)) {
            throw new RuntimeException("Index not ready");
        }
        // Composed ID
        String id = String.format(Locale.ROOT, "%s_%s", consumer.getContext(), consumer.getName());
        IndexRequest request = new IndexRequest()
            .index(INDEX_NAME)
            .id(id)
            .source(consumer.toXContent());

        return this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    public GetResponse getConsumer(String context, String consumer) throws ExecutionException, InterruptedException, TimeoutException {
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

    /** TODO: Review ConsumerInfo class and adapt mappings accordingly */
    /**
     * Searches for the given consumer within a context.
     *
     * @param context ID (name) of the context.
     * @param consumer ID (name) of the consumer.
     * @return the required consumer as an instance of {@link ConsumerInfo}, or null.
     */
    @SuppressWarnings("unchecked")
    public ConsumerInfo get(String context, String consumer) {
        // Avoid faulty requests if the cluster is unstable.
        if (!ClusterInfo.indexStatusCheck(this.client, ConsumersIndex.INDEX_NAME)) {
            throw new RuntimeException("Index not ready");
        }
        try {
            GetResponse getResponse =
                    this.client
                            .get(new GetRequest(ConsumersIndex.INDEX_NAME, context).preference("_local"))
                            .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

            Map<String, Object> source = (Map<String, Object>) getResponse.getSourceAsMap().get(consumer);
            if (source == null) {
                throw new NoSuchElementException(
                        String.format(
                                Locale.ROOT, "Consumer [%s] not found in context [%s]", consumer, context));
            }

            // Update consumer info (internal state)
            long offset = ConsumersIndex.asLong(source.get(ConsumerInfo.OFFSET));
            long lastOffset = ConsumersIndex.asLong(source.get(ConsumerInfo.LAST_OFFSET));
            String snapshot = (String) source.get(ConsumerInfo.LAST_SNAPSHOT_LINK);
            this.consumerInfo = new ConsumerInfo(consumer, context, offset, lastOffset, snapshot);
            log.info(
                    "Fetched consumer from the [{}] index: {}", ConsumersIndex.INDEX_NAME, this.consumerInfo);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Failed to fetch consumer [{}][{}]: {}", context, consumer, e.getMessage());
        }

        // May be null if the request fails and was not initialized on previously.
        return this.consumerInfo;
    }

    /**
     * Utility method to parse an object value to primitive long.
     *
     * @param o the object to parse.
     * @return the value as primitive long.
     */
    private static long asLong(Object o) {
        return o instanceof Number ? ((Number) o).longValue() : Long.parseLong(o.toString());
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
   public void createIndex() {
        try {
            String mappingJson = this.loadMappingFromResources();

            CreateIndexRequest request = new CreateIndexRequest(ConsumersIndex.INDEX_NAME);

            // Index settings
            request.settings(Settings.builder().put("index.number_of_replicas", 0).build());
            request.mapping(mappingJson, XContentType.JSON);

        CreateIndexResponse response = this.client
            .admin()
            .indices()
            .create(request)
            .actionGet(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
            log.info("Index created: {} acknowledged={}", response.index(), response.isAcknowledged());

        } catch (Exception e) {
            log.warn("Index creation attempt failed: {}", e.getMessage());
        }
    }

    /**
     * Loads the index mapping from the resources folder.
     *
     * @return the mapping as a JSON string.
     * @throws IOException if reading the resource fails.
     */
    private String loadMappingFromResources() throws IOException {
        try (InputStream is = this.getClass().getResourceAsStream(MAPPING_PATH)) {
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
