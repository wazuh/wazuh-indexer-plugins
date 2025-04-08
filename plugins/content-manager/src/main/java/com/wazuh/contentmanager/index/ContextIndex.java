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

/** Class to manage the Context index. */
public class ContextIndex {
    private static final Logger log = LogManager.getLogger(ContextIndex.class);

    /** The name of the Contexts index */
    public static final String INDEX_NAME = "wazuh-context";

    /** Timeout of indexing operations */
    public static final Long TIMEOUT = 10L;

    private final Client client;

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
     */
    public void index(ConsumerInfo consumerInfo) {

        IndexRequest indexRequest = null;
        try {
            indexRequest =
                    new IndexRequest()
                            .index(INDEX_NAME)
                            .source(
                                    consumerInfo.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS))
                            .id(consumerInfo.getContext())
                            .create(true);
        } catch (IOException e) {
            log.error("Failed to create JSON content builder: {}", e.getMessage());
        }

        this.client.index(
                indexRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        log.info("Successfully initialized consumer [{}]", consumerInfo.getContext());
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(
                                "Failed to index Consumer [{}] information due to: {}",
                                consumerInfo.getContext(),
                                e);
                    }
                });
    }

    /**
     * Get a context off its index
     *
     * @param contextName ID of the context to be retrieved
     * @return A completable future holding the response of the query
     */
    public CompletableFuture<GetResponse> get(String contextName) {

        GetRequest getRequest = new GetRequest(INDEX_NAME, contextName);

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
        try {
            GetResponse getResponse = get(context).get(TIMEOUT, TimeUnit.SECONDS);
            log.info("Received search response for {}", context);

            Map<String, Object> source = (Map<String, Object>) getResponse.getSourceAsMap().get(consumer);
            if (source == null) {
                log.warn("Consumer {} not found in context {}", consumer, context);
                return null;
            }

            Object offsetObj = source.get(ConsumerInfo.LAST_OFFSET);
            Long last_offset = (offsetObj instanceof Number) ? ((Number) offsetObj).longValue() : null;
            String snapshot = (String) source.get(ConsumerInfo.LAST_SNAPSHOT_LINK);
            return new ConsumerInfo(consumer, context, last_offset, snapshot);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error(
                    "Failed to retrieve context [{}], consumer [{}]: {}", context, consumer, e.getMessage());
        }
        return null;
    }
}
