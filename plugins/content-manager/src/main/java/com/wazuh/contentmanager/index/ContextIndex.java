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
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.ToXContent;

import java.io.IOException;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;

/** Class to manage the Context index. */
public class ContextIndex {
    private static final Logger log = LogManager.getLogger(ContextIndex.class);

    /** The name of the Contexts index */
    public static final String CONTEXTS_INDEX = "wazuh-context";

    /** Timeout of indexing operations */
    public static final Long TIMEOUT = 10L;

    private final Client client;
    private ConsumerInfo consumerInfo;

    /**
     * Constructor for the class.
     *
     * @param client Necessary for index and search operations
     */
    public ContextIndex(Client client) {
        this.client = client;
    }

    /**
     * Index CTI API consumer information
     *
     * @param consumerInfo Model containing information parsed from the CTI API
     * @return the IndexResponse from the indexing operation
     */
    public IndexResponse index(ConsumerInfo consumerInfo) {
        IndexRequest indexRequest = null;
        IndexResponse indexResponse = null;
        // Set this to null so that future get() operations need to read the values from the index
        this.consumerInfo = null;
        try {
            indexRequest =
                    new IndexRequest()
                            .index(CONTEXTS_INDEX)
                            .source(
                                    consumerInfo.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .id(consumerInfo.getContext())
                            .create(true);
        } catch (IOException e) {
            log.error("Failed to create JSON content builder: {}", e.getMessage());
        }

        PlainActionFuture<IndexResponse> future = new PlainActionFuture<>();
        this.client.index(indexRequest, future);
        try {
            indexResponse = future.get(TIMEOUT, TimeUnit.SECONDS);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Failed to index Consumer [{}] information due to: {}",
                    consumerInfo.getContext(),
                    e.getMessage());
            return null;
        }
        return indexResponse;
    }

    /**
     * Get a context off its index
     *
     * @param contextName ID of the context to be retrieved
     * @return A completable future holding the response of the query
     */
    public CompletableFuture<GetResponse> get(String contextName) {

        GetRequest getRequest = new GetRequest(CONTEXTS_INDEX, contextName);

        CompletableFuture<GetResponse> future = new CompletableFuture<>();

        this.client.get(
                getRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(GetResponse getResponse) {
                        log.info("Retrieved CTI Catalog Context {} from index", contextName);
                        future.complete(getResponse);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to retrieve CTI Catalog Context {}, Exception: {}", contextName, e);
                        future.completeExceptionally(e);
                    }
                });
        return future;
    }

    /**
     * Wrapper for get() that returns a single consumer out of the contexts index
     *
     * @param context Context to get from index
     * @param consumer Consumer name to retrieve from context document
     * @return a ConsumerInfo object
     */
    @SuppressWarnings("unchecked")
    public ConsumerInfo getConsumer(String context, String consumer) {
        if (this.consumerInfo != null) {
            return this.consumerInfo;
        }
        try {
            GetResponse getResponse = get(context).get(TIMEOUT, TimeUnit.SECONDS);
            log.info("Received search response for {}", context);

            Map<String, Object> source = (Map<String, Object>) getResponse.getSourceAsMap().get(consumer);
            if (source == null) {
                log.warn("Consumer {} not found in context {}", consumer, context);
                return null;
            }

            Object lastOffsetObj = source.get(ConsumerInfo.LAST_OFFSET);
            Long lastOffset =
                    (lastOffsetObj instanceof Number) ? ((Number) lastOffsetObj).longValue() : null;
            Object offsetObj = source.get(ConsumerInfo.OFFSET);
            Long offset = (offsetObj instanceof Number) ? ((Number) offsetObj).longValue() : null;
            String snapshot = (String) source.get(ConsumerInfo.LAST_SNAPSHOT_LINK);
            this.consumerInfo = new ConsumerInfo(consumer, context, offset, lastOffset, snapshot);
            return this.consumerInfo;
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Failed to retrieve context [{}], consumer [{}]: {}", context, consumer, e.getMessage());
        }
        return null;
    }

    /**
     * Returns the current offset from the context index
     *
     * @return The long value of the offset
     */
    public Long getOffset() {
        return getConsumer(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID).getOffset();
    }

    /**
     * Returns the current offset from the context index
     *
     * @return The long value of the offset
     */
    public Long getLastOffset() {
        return getConsumer(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID).getLastOffset();
    }

    /**
     * Returns the last snapshot link from the context index
     *
     * @return a String with the last snapshot link
     */
    public String getLastSnapshotLink() {
        return getConsumer(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID).getLastSnapshotLink();
    }
}
