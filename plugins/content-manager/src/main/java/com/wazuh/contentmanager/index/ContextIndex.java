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
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.ToXContent;

import java.io.IOException;
import java.util.Locale;
import java.util.Map;
import java.util.NoSuchElementException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;

/** Class to manage the Context index. */
public class ContextIndex {
    private static final Logger log = LogManager.getLogger(ContextIndex.class);

    /** The name of the Contexts index */
    public static final String INDEX_NAME = "wazuh-context";

    /** Timeout of indexing operations */
    private static final long TIMEOUT = 10L;

    private final Client client;
    private ConsumerInfo consumerInfo;

    /**
     * Constructor.
     *
     * @param client OpenSearch client used for indexing and search operations.
     */
    public ContextIndex(Client client) {
        this.client = client;
        this.consumerInfo =
                new ConsumerInfo(PluginSettings.CONSUMER_ID, PluginSettings.CONTEXT_ID, 0, 0, null);
    }

    //    /**
    //     * offset: 0, last_offset: 0
    //     */
    //    public void init() {
    //        IndexRequest indexRequest =
    //            new IndexRequest()
    //                .index(ContextIndex.INDEX_NAME)
    //                .source(
    //                    new ConsumerInfo(PluginSettings.CONSUMER_ID, PluginSettings.CONTEXT_ID, 0,
    // 0, null))
    //                .id(consumerInfo.getContext());
    //
    //        this.client.index(indexRequest, new ActionListener<>() {
    //            @Override
    //            public void onResponse(IndexResponse indexResponse) {
    //                log.info("Context consumer [{}-{}] successfully initialized",
    // PluginSettings.CONSUMER_ID, PluginSettings.CONTEXT_ID);
    //            }
    //
    //            @Override
    //            public void onFailure(Exception e) {
    //                log.error("Failed to initialize context consumer [{}-{}] due to {}",
    // PluginSettings.CONSUMER_ID, PluginSettings.CONTEXT_ID, e.getMessage());
    //            }
    //        });
    //    }
    //
    //    /**
    //     * event: scheduled_update, offset: unchanged, last_offset: response.last_offset
    //     * @param offset
    //     */
    //    public void setLastOffset(long offset) {
    //
    //    }
    //
    //    /**
    //     * event: content_update, offset: last_indexed_item.offset, last_offset: unchanged
    //     * @param offset
    //     */
    //    public void setOffset(long offset) {
    //
    //    }

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
                            .index(ContextIndex.INDEX_NAME)
                            .source(
                                    consumerInfo.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .id(consumerInfo.getContext());

            IndexResponse indexResponse = this.client.index(indexRequest).get(TIMEOUT, TimeUnit.SECONDS);
            if (indexResponse.getResult() == DocWriteResponse.Result.CREATED
                    || indexResponse.getResult() == DocWriteResponse.Result.UPDATED) {
                // Update consumer info.
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

    //    /**
    //     * Get a context by ID (name).
    //     *
    //     * @param contextName ID of the context to be retrieved.
    //     * @return A completable future holding the response of the query.
    //     */
    //    public CompletableFuture<GetResponse> get(@NonNull String contextName) {
    //        GetRequest request = new GetRequest(ContextIndex.INDEX_NAME, contextName);
    //        CompletableFuture<GetResponse> future = new CompletableFuture<>();
    //
    //        this.client.get(
    //                request,
    //                new ActionListener<>() {
    //                    @Override
    //                    public void onResponse(GetResponse getResponse) {
    //                        log.info("Retrieved CTI Catalog Context {} from index", contextName);
    //                        future.complete(getResponse);
    //                    }
    //
    //                    @Override
    //                    public void onFailure(Exception e) {
    //                        log.error("Failed to retrieve CTI Catalog Context {}, Exception: {}",
    // contextName, e);
    //                        future.completeExceptionally(e);
    //                    }
    //                });
    //        return future;
    //    }

    /**
     * Get a consumer of a context by their IDs.
     *
     * @param context ID (name) of the context.
     * @param consumer ID (name) of the consumer.
     * @return the required consumer as an instance of {@link ConsumerInfo}, or null.
     */
    @SuppressWarnings("unchecked")
    public ConsumerInfo getConsumer(String context, String consumer) {
        try {
            GetResponse getResponse =
                    this.client
                            .get(new GetRequest(ContextIndex.INDEX_NAME, context).refresh(true))
                            .get(ContextIndex.TIMEOUT, TimeUnit.SECONDS);

            Map<String, Object> source = (Map<String, Object>) getResponse.getSourceAsMap().get(consumer);
            if (source == null) {
                throw new NoSuchElementException(
                        String.format(
                                Locale.ROOT, "Consumer [%s] not found in context [%s]", consumer, context));
            }
            log.info("Found [{}][{}] context consumer in the [{}] index", context, consumer, INDEX_NAME);

            long offset = ContextIndex.asLong(source.get(ConsumerInfo.OFFSET));
            long lastOffset = ContextIndex.asLong(source.get(ConsumerInfo.LAST_OFFSET));
            String snapshot = (String) source.get(ConsumerInfo.LAST_SNAPSHOT_LINK);
            this.consumerInfo = new ConsumerInfo(consumer, context, offset, lastOffset, snapshot);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Failed to retrieve context [{}], consumer [{}]: {}", context, consumer, e.getMessage());
        }

        return this.consumerInfo;
    }

    //    /**
    //     * Returns the current offset from the context index.
    //     *
    //     * @return The long value of the offset.
    //     */
    //    public long getOffset() {
    //        return this.getConsumer(PluginSettings.CONTEXT_ID,
    // PluginSettings.CONSUMER_ID).getOffset();
    //    }

    //    /**
    //     * Returns the current offset from the context index.
    //     *
    //     * @return The long value of the offset.
    //     */
    //    public long getLastOffset() {
    //        return this.getConsumer(PluginSettings.CONTEXT_ID,
    // PluginSettings.CONSUMER_ID).getLastOffset();
    //    }

    //    /**
    //     * Returns the last snapshot link from the context index.
    //     *
    //     * @return a String with the last snapshot link.
    //     */
    //    public String getLastSnapshotLink() {
    //        return this.getConsumer(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID)
    //                .getLastSnapshotLink();
    //    }

    /**
     * Utility method to parse an object value to primitive long.
     *
     * @param o the object to parse.
     * @return the value as primitive long.
     */
    private static long asLong(Object o) {
        return o instanceof Number ? ((Number) o).longValue() : Long.parseLong(o.toString());
    }

    //    /**
    //     * Sets the context index current and last offset.
    //     *
    //     * <p>ContextIndex.setOffset(offset).
    //     */
    //    public void setOffset(Long offset, Long lastOffset) {
    //        this.index(
    //                new ConsumerInfo(
    //                        PluginSettings.CONSUMER_ID, PluginSettings.CONTEXT_ID, offset,
    // lastOffset, null));
    //        log.info("Updated context index with new offset {} and last offset {}", offset,
    // lastOffset);
    //    }

    //    /**
    //     * Sets the context index current offset, maintaining the same last offset value.
    //     *
    //     * <p>ContextIndex.setOffset(offset).
    //     *
    //     * @param offset Long value of the new offset.
    //     */
    //    public void setOffset(Long offset) {
    //        this.index(
    //                new ConsumerInfo(
    //                        PluginSettings.CONSUMER_ID,
    //                        PluginSettings.CONTEXT_ID,
    //                        offset,
    //                        this.getLastOffset(),
    //                        null));
    //        log.info("Updated context index with new offset {}", offset);
    //    }
}
