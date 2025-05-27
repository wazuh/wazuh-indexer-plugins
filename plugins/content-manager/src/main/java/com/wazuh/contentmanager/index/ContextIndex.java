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
package com.wazuh.contentmanager.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.model.cti.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;

/** Class to manage the Context index. */
public class ContextIndex {
    private static final Logger log = LogManager.getLogger(ContextIndex.class);

    /** The name of the Contexts index */
    public static final String INDEX_NAME = "wazuh-context";

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
    public ContextIndex(Client client) {
        this.client = client;
        this.pluginSettings = PluginSettings.getInstance();
    }

    /**
     * Constructor that allows to inject pluginSettings
     *
     * @param client OpenSearch client used for indexing and search operations.
     * @param pluginSettings Plugin settings used for configuration.
     */
    public ContextIndex(Client client, PluginSettings pluginSettings) {
        this.client = client;
        this.pluginSettings = pluginSettings;
    }

    /**
     * Index CTI API consumer information.
     *
     * @param consumerInfo Model containing information parsed from the CTI API.
     * @return true if the index was created or updated, false otherwise.
     */
    public boolean index(ConsumerInfo consumerInfo) {
        return index(consumerInfo, false);
    }

    /**
     * Index CTI API consumer information.
     *
     * @param consumerInfo Model containing information parsed from the CTI API.
     * @param createIndex true if the index should be created if it does not exist, false otherwise.
     * @return the IndexResponse from the indexing operation, or null.
     */
    public boolean index(ConsumerInfo consumerInfo, boolean createIndex) {
        try {
            IndexRequest indexRequest =
                    new IndexRequest()
                            .index(ContextIndex.INDEX_NAME)
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

    /**
     * Get a consumer of a context by their IDs.
     *
     * @param context ID (name) of the context.
     * @param consumer ID (name) of the consumer.
     * @return the required consumer as an instance of {@link ConsumerInfo}, or null.
     * @throws OpenSearchStatusException if the index is not available.
     */
    @SuppressWarnings("unchecked")
    public ConsumerInfo get(String context, String consumer) throws OpenSearchStatusException {
        // Avoid faulty requests if the cluster is unstable.
        if (!ClusterInfo.indexStatusCheck(this.client, ContextIndex.INDEX_NAME)) {
            throw new OpenSearchStatusException(
                    String.format(
                            Locale.ROOT,
                            "The index [%s] is not available. Please check the cluster status.",
                            ContextIndex.INDEX_NAME),
                    RestStatus.SERVICE_UNAVAILABLE);
        }
        try {
            GetResponse getResponse =
                    this.client
                            .get(new GetRequest(ContextIndex.INDEX_NAME, context).preference("_local"))
                            .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);

            Map<String, Object> source = (Map<String, Object>) getResponse.getSourceAsMap().get(consumer);
            if (source == null) {
                throw new NoSuchElementException(
                        String.format(
                                Locale.ROOT, "Consumer [%s] not found in context [%s]", consumer, context));
            }
            // Update consumer info (internal state)
            long offset = ContextIndex.asLong(source.get(ConsumerInfo.OFFSET));
            long lastOffset = ContextIndex.asLong(source.get(ConsumerInfo.LAST_OFFSET));
            String snapshot = (String) source.get(ConsumerInfo.LAST_SNAPSHOT_LINK);
            this.consumerInfo = new ConsumerInfo(consumer, context, offset, lastOffset, snapshot);
            log.info(
                    "Fetched consumer from the [{}] index: {}", ContextIndex.INDEX_NAME, this.consumerInfo);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Failed to fetch consumer [{}][{}]: {}", context, consumer, e.getMessage());
            this.consumerInfo = new ConsumerInfo(consumer, context, 0L, 0L, "");
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
     * Checks whether the {@link ContextIndex#INDEX_NAME} index exists.
     *
     * @see ClusterInfo#indexExists(Client, String)
     * @return true if the index exists, false otherwise.
     */
    public boolean exists() {
        return ClusterInfo.indexExists(this.client, ContextIndex.INDEX_NAME);
    }

    /** Creates the {@link ContextIndex#INDEX_NAME} index, if it does not exist. */
    public void createIndex() {
        if (!this.exists()) {
            boolean result =
                    this.index(
                            new ConsumerInfo(
                                    this.pluginSettings.getConsumerId(),
                                    this.pluginSettings.getContextId(),
                                    0,
                                    0,
                                    null));
            log.info("Index initialized: {}", result);
        }
    }
}
