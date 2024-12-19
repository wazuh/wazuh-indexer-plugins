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

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.CreatePitRequest;
import org.opensearch.action.search.CreatePitResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.Client;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.*;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.PointInTimeBuilder;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.search.sort.SortOrder;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.AccessController;
import java.security.PrivilegedAction;
import java.util.*;
import java.util.concurrent.CancellationException;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.model.Document;
import com.wazuh.commandmanager.model.Order;
import com.wazuh.commandmanager.model.Status;
import com.wazuh.commandmanager.settings.PluginSettings;
import com.wazuh.commandmanager.utils.httpclient.AuthHttpRestClient;

/**
 * The class in charge of searching and managing commands in {@link Status#PENDING} status and of
 * submitting them to the destination client.
 */
public class SearchThread implements Runnable {
    public static final String COMMAND_STATUS_FIELD = Command.COMMAND + "." + Command.STATUS;
    public static final String DELIVERY_TIMESTAMP_FIELD = Document.DELIVERY_TIMESTAMP;
    private static final Logger log = LogManager.getLogger(SearchThread.class);
    public static final String ORDERS_ENDPOINT = "/orders";
    private final SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
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
     * Retrieves a nested value from a {@code Map<String, Object>} in a (somewhat) safe way.
     *
     * @param map The parent map to look at.
     * @param key The key our nested object is found under.
     * @param type The type we expect the nested object to be of.
     * @param <T> The type of the nested object.
     * @return the nested object cast into the proper type.
     */
    public static <T> T getNestedObject(Map<String, Object> map, String key, Class<T> type) {
        final Object value = map.get(key);
        if (value == null) {
            return null;
        }
        if (type.isInstance(value)) {
            // Make a defensive copy for supported types like Map or List
            if (value instanceof Map) {
                return type.cast(new HashMap<>((Map<?, ?>) value));
            } else if (value instanceof List) {
                return type.cast(new ArrayList<>((List<?>) value));
            }
            // Return the value directly if it is immutable (e.g., String, Integer)
            return type.cast(value);
        } else {
            throw new ClassCastException(
                    "Expected " + type.getName() + " but found " + value.getClass().getName());
        }
    }

    /**
     * Iterates over search results, updating their status field and submitting them to the
     * destination
     *
     * @param searchResponse The search results page
     * @throws IllegalStateException Rethrown from setSentStatus()
     */
    @SuppressWarnings("unchecked")
    public void handlePage(SearchResponse searchResponse) throws IllegalStateException {
        SearchHits searchHits = searchResponse.getHits();
        String payload = null;
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            // Start an XContentBuilder array named "orders"
            builder.startObject();
            builder.startArray(Order.ORDERS);
            // Iterate over search results
            for (SearchHit hit : searchHits) {
                // Create a parser for each SearchHit
                XContentParser parser =
                        XContentHelper.createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.IGNORE_DEPRECATIONS,
                                hit.getSourceRef(),
                                XContentType.JSON);
                // Parse the hit's order
                Order order = Order.parseSearchHit(hit);
                // Add the current order to the XContentBuilder array
                assert order != null;
                order.toXContent(builder, ToXContent.EMPTY_PARAMS);
            }
            // Close the object and prepare it for delivery
            builder.endArray();
            builder.endObject();
            payload = builder.toString();
        } catch (IOException e) {
            log.error("Error building payload from hit: {}", e.getMessage());
        }
        final SimpleHttpResponse response = deliverOrders(payload);
        if (response == null) {
            log.error("No reply from server.");
            return;
        }
        log.info("Server replied with {}. Updating orders' status.", response.getCode());
        Status status = Status.FAILURE;
        if (List.of(RestStatus.CREATED, RestStatus.ACCEPTED, RestStatus.OK)
                .contains(RestStatus.fromCode(response.getCode()))) {
            status = Status.SENT;
        }
        for (SearchHit hit : searchHits) {
            this.setSentStatus(hit, status);
        }
    }

    /**
     * Send the command order over HTTP
     *
     * @param orders The list of order to send.
     */
    private SimpleHttpResponse deliverOrders(String orders) {
        SimpleHttpResponse response = null;
        try {
            final PluginSettings settings = PluginSettings.getInstance();
            final URI host =
                    new URIBuilder(settings.getUri() + SearchThread.ORDERS_ENDPOINT).build();

            response =
                    AccessController.doPrivileged(
                            (PrivilegedAction<SimpleHttpResponse>)
                                    () -> {
                                        final AuthHttpRestClient httpClient =
                                                new AuthHttpRestClient();
                                        return httpClient.post(host, orders, null);
                                    });
        } catch (URISyntaxException e) {
            log.error("Invalid URI: {}", e.getMessage());
        } catch (Exception e) {
            log.error("Error sending data: {}", e.getMessage());
        }
        return response;
    }

    /**
     * Retrieves the hit's contents and updates the {@link Status} field to {@link Status#SENT}.
     *
     * @param hit The page's result we are to update.
     * @throws IllegalStateException Raised by {@link ActionFuture#actionGet(long)}.
     */
    @SuppressWarnings("unchecked")
    private void setSentStatus(SearchHit hit, Status status) throws IllegalStateException {
        final Map<String, Object> commandMap =
                getNestedObject(
                        hit.getSourceAsMap(),
                        CommandManagerPlugin.COMMAND_DOCUMENT_PARENT_OBJECT_NAME,
                        Map.class);
        commandMap.put(Command.STATUS, status);
        hit.getSourceAsMap()
                .put(CommandManagerPlugin.COMMAND_DOCUMENT_PARENT_OBJECT_NAME, commandMap);
        final IndexRequest indexRequest =
                new IndexRequest()
                        .index(CommandManagerPlugin.INDEX_NAME)
                        .source(hit.getSourceAsMap())
                        .id(hit.getId());
        this.client
                .index(indexRequest)
                .actionGet(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS * 1000);
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
            throws IllegalStateException {
        final SearchRequest searchRequest = new SearchRequest(CommandManagerPlugin.INDEX_NAME);
        final TermQueryBuilder termQueryBuilder =
                QueryBuilders.termQuery(SearchThread.COMMAND_STATUS_FIELD, Status.PENDING);
        final TimeValue timeout =
                TimeValue.timeValueSeconds(CommandManagerPlugin.DEFAULT_TIMEOUT_SECONDS);
        this.searchSourceBuilder
                .query(termQueryBuilder)
                .size(CommandManagerPlugin.PAGE_SIZE)
                .trackTotalHits(true)
                .timeout(timeout)
                .pointInTimeBuilder(pointInTimeBuilder);
        if (this.searchSourceBuilder.sorts() == null) {
            this.searchSourceBuilder.sort(SearchThread.DELIVERY_TIMESTAMP_FIELD, SortOrder.ASC);
        }
        if (searchAfter.length > 0) {
            this.searchSourceBuilder.searchAfter(searchAfter);
        }
        searchRequest.source(this.searchSourceBuilder);
        return this.client.search(searchRequest).actionGet(timeout);
    }

    @Override
    public void run() {
        log.debug("Running scheduled job");
        long consumableHits = 0L;
        boolean firstPage = true;
        final PointInTimeBuilder pointInTimeBuilder = buildPit();
        try {
            do {
                this.currentPage =
                        pitQuery(
                                pointInTimeBuilder,
                                getSearchAfter(this.currentPage).orElse(new Object[0]));
                if (firstPage) {
                    log.debug("Query returned {} hits.", totalHits());
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
        } catch (Exception e) {
            log.error("Generic exception retrieving page: {}", e.getMessage());
            e.printStackTrace();
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

    /**
     * Gets the sort values of the last hit of a page. It is used by a PIT search to get the next
     * page of results.
     *
     * @param searchResponse The current page
     * @return The values of the sort fields of the last hit of a page whenever present. Otherwise,
     *     an empty Optional.
     */
    private Optional<Object[]> getSearchAfter(SearchResponse searchResponse) {
        if (searchResponse == null) {
            return Optional.empty();
        }
        try {
            final List<SearchHit> hits = Arrays.asList(searchResponse.getHits().getHits());
            if (hits.isEmpty()) {
                log.warn("Empty hits page, not getting searchAfter values");
                return Optional.empty();
            }
            return Optional.ofNullable(hits.get(hits.size() - 1).getSortValues());
        } catch (NullPointerException | NoSuchElementException e) {
            log.error("Could not get the page's searchAfter values: {}", e.getMessage());
            return Optional.empty();
        }
    }

    /**
     * Prepares a PointInTimeBuilder object to be used in a search.
     *
     * @return a PointInTimeBuilder or null.
     */
    private PointInTimeBuilder buildPit() {
        final CompletableFuture<CreatePitResponse> future = new CompletableFuture<>();
        final ActionListener<CreatePitResponse> actionListener =
                new ActionListener<>() {
                    @Override
                    public void onResponse(CreatePitResponse createPitResponse) {
                        future.complete(createPitResponse);
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(e.getMessage());
                        future.completeExceptionally(e);
                    }
                };
        this.client.createPit(
                new CreatePitRequest(
                        CommandManagerPlugin.PIT_KEEP_ALIVE_SECONDS,
                        false,
                        CommandManagerPlugin.INDEX_NAME),
                actionListener);
        try {
            return new PointInTimeBuilder(future.get().getId());
        } catch (CancellationException e) {
            log.error("Building PIT was cancelled: {}", e.getMessage());
        } catch (ExecutionException e) {
            log.error("Error building PIT: {}", e.getMessage());
        } catch (InterruptedException e) {
            log.error("Building PIT was interrupted: {}", e.getMessage());
        }
        return null;
    }
}
