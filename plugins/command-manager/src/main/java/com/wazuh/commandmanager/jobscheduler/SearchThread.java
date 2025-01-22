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
package com.wazuh.commandmanager.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchTimeoutException;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.time.DateUtils;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.PointInTimeBuilder;
import org.opensearch.search.sort.SortOrder;

import java.time.ZonedDateTime;
import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.*;
import com.wazuh.commandmanager.utils.Search;

/**
 * The class in charge of searching and managing commands in {@link Status#PENDING} status and of
 * submitting them to the destination client.
 */
public class SearchThread implements Runnable {
    public static final String COMMAND_STATUS_FIELD = Command.COMMAND + "." + Command.STATUS;
    public static final String DELIVERY_TIMESTAMP_FIELD = Order.DELIVERY_TIMESTAMP;
    private static final Logger log = LogManager.getLogger(SearchThread.class);
    private final Client client;
    private SearchResponse currentPage = null;

    /**
     * Default constructor.
     *
     * @param client OpenSearch's client.
     */
    public SearchThread(Client client) {
        this.client = client;
    }

    /**
     * Iterates over search results, updating their status field to {@link Status#FAILURE} if their
     * delivery timestamps are earlier than the current time.
     *
     * @param searchResponse The search results page.
     * @throws IllegalStateException from setFailureStatus()
     * @throws OpenSearchTimeoutException from setFailureStatus()
     */
    public void handlePage(SearchResponse searchResponse)
            throws IllegalStateException, OpenSearchTimeoutException {
        SearchHits searchHits = searchResponse.getHits();

        final ZonedDateTime current_time = DateUtils.nowWithMillisResolution();

        for (SearchHit hit : searchHits) {
            final ZonedDateTime deliveryTimestampFromSearchHit =
                    Order.deliveryTimestampFromSearchHit(hit);
            if (deliveryTimestampFromSearchHit != null
                    && deliveryTimestampFromSearchHit.isBefore(current_time)) {
                this.setFailureStatus(hit);
            }
        }
    }

    /**
     * Retrieves the hit's contents and updates the {@link Status} field to {@link Status#FAILURE}.
     *
     * @param hit The page's result we are to update.
     * @throws IllegalStateException Raised by {@link ActionFuture#actionGet(long)}.
     * @throws OpenSearchTimeoutException Raised by {@link ActionFuture#actionGet(long)}.
     */
    @SuppressWarnings("unchecked")
    private void setFailureStatus(SearchHit hit)
            throws IllegalStateException, OpenSearchTimeoutException {
        final Map<String, Object> commandMap =
                Search.getNestedObject(
                        hit.getSourceAsMap(),
                        CommandManagerPlugin.COMMAND_DOCUMENT_PARENT_OBJECT_NAME,
                        Map.class);

        if (commandMap != null) {
            commandMap.put(Command.STATUS, Status.FAILURE);
            hit.getSourceAsMap()
                    .put(CommandManagerPlugin.COMMAND_DOCUMENT_PARENT_OBJECT_NAME, commandMap);
            final IndexRequest indexRequest =
                    new IndexRequest()
                            .index(CommandManagerPlugin.INDEX_NAME)
                            .source(hit.getSourceAsMap())
                            .id(hit.getId());
            this.client
                    .index(indexRequest)
                    .actionGet(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS, TimeUnit.SECONDS);
        }
    }

    /**
     * Runs a PIT style query against the Commands index.
     *
     * @param pointInTimeBuilder A pit builder object used to run the query.
     * @param searchAfter An array of objects containing the last page's values of the sort fields.
     * @return The search response.
     * @throws IllegalStateException Raised by {@link ActionFuture#actionGet(long)}.
     */
    public SearchResponse pitQuery(PointInTimeBuilder pointInTimeBuilder, Object[] searchAfter)
            throws IllegalStateException, OpenSearchTimeoutException {
        return Search.executePitQuery(
                this.client,
                CommandManagerPlugin.INDEX_NAME,
                SearchThread.COMMAND_STATUS_FIELD,
                String.valueOf(Status.PENDING),
                pointInTimeBuilder,
                searchAfter,
                TimeValue.timeValueSeconds(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS),
                CommandManagerPlugin.PAGE_SIZE,
                DELIVERY_TIMESTAMP_FIELD,
                SortOrder.ASC);
    }

    @Override
    public void run() {
        log.debug("Running scheduled job");
        long consumableHits = 0L;
        boolean firstPage = true;
        final PointInTimeBuilder pointInTimeBuilder =
                Search.buildPit(
                        client,
                        CommandManagerPlugin.PIT_KEEP_ALIVE_SECONDS,
                        CommandManagerPlugin.INDEX_NAME);
        try {
            do {
                this.currentPage =
                        pitQuery(
                                pointInTimeBuilder,
                                Search.getSearchAfter(this.currentPage).orElse(new Object[0]));
                if (firstPage) {
                    log.info("Query returned {} hits.", totalHits());
                    consumableHits = totalHits();
                    firstPage = false;
                }
                if (consumableHits > 0) {
                    handlePage(this.currentPage);
                    consumableHits -= getPageLength();
                }
            } while (consumableHits > 0);
        } catch (ArrayIndexOutOfBoundsException e) {
            log.error("ArrayIndexOutOfBoundsException retrieving page: {}", e.getMessage());
        } catch (IllegalStateException e) {
            log.error("IllegalStateException retrieving page: {}", e.getMessage());
        } catch (OpenSearchTimeoutException e) {
            log.error("Query timed out: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Generic exception retrieving page: {}", e.getMessage());
        }
    }

    /**
     * @return SearchResponse hits.
     */
    private long getPageLength() {
        return this.currentPage.getHits().getHits().length;
    }

    /**
     * @return SearchResponse total hits.
     */
    private long totalHits() {
        if (this.currentPage.getHits().getTotalHits() != null) {
            return this.currentPage.getHits().getTotalHits().value;
        } else {
            return 0;
        }
    }
}
