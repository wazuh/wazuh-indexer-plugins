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

    /**
     * Searches for the given consumer within a context.
     *
     * @param context ID (name) of the context.
     * @param consumer ID (name) of the consumer.
     * @return the required consumer as an instance of {@link ConsumerInfo}, or null.
     */
    @SuppressWarnings("unchecked")
    public ConsumerInfo get(String context, String consumer) {
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

            long offset = ContextIndex.asLong(source.get(ConsumerInfo.OFFSET));
            long lastOffset = ContextIndex.asLong(source.get(ConsumerInfo.LAST_OFFSET));
            String snapshot = (String) source.get(ConsumerInfo.LAST_SNAPSHOT_LINK);
            this.consumerInfo = new ConsumerInfo(consumer, context, offset, lastOffset, snapshot);
            log.info("Fetched consumer from [{}] index: {}", INDEX_NAME, this.consumerInfo);
        } catch (InterruptedException | ExecutionException | TimeoutException e) {
            log.error("Failed to fetch consumer [{}][{}]: {}", context, consumer, e.getMessage());
        }

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
}
