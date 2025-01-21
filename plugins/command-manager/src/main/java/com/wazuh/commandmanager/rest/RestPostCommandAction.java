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
package com.wazuh.commandmanager.rest;

import com.wazuh.commandmanager.model.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.index.query.BoolQueryBuilder;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.index.CommandIndex;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.search.builder.SearchSourceBuilder;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * Handles HTTP requests to the POST {@value
 * com.wazuh.commandmanager.CommandManagerPlugin#COMMANDS_URI} endpoint.
 */
public class RestPostCommandAction extends BaseRestHandler {

    public static final String POST_COMMAND_ACTION_REQUEST_DETAILS =
            "post_command_action_request_details";
    private static final Logger log = LogManager.getLogger(RestPostCommandAction.class);
    private final CommandIndex commandIndex;

    /**
     * Default constructor
     *
     * @param commandIndex persistence layer
     */
    public RestPostCommandAction(CommandIndex commandIndex) {
        this.commandIndex = commandIndex;
    }

    public String getName() {
        return POST_COMMAND_ACTION_REQUEST_DETAILS;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(
                        POST, String.format(Locale.ROOT, "%s", CommandManagerPlugin.COMMANDS_URI)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client)
            throws IOException {
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            default:
                throw new IllegalArgumentException(
                        "Unsupported HTTP method " + request.method().name());
        }
    }

    /**
     * Handles a POST HTTP request.
     *
     * @param request POST HTTP request
     * @return a response to the request as BytesRestResponse.
     * @throws IOException thrown by the XContentParser methods.
     */
    @SuppressWarnings("unchecked")
    private RestChannelConsumer handlePost(RestRequest request, final NodeClient client) throws IOException {
        log.info(
                "Received {} {} request id [{}] from host [{}]",
                request.method().name(),
                request.uri(),
                request.getRequestId(),
                request.header("Host"));

        /// Request validation
        /// ==================
        /// Fail fast.
        if (!request.hasContent()) {
            // Bad request if body doesn't exist
            return channel -> {
                channel.sendResponse(
                        new BytesRestResponse(RestStatus.BAD_REQUEST, "Body content is required"));
            };
        }

        /// Request parsing
        /// ===============
        /// Retrieves and generates an array list of commands.
        XContentParser parser = request.contentParser();
        List<Command> commands = new ArrayList<>();
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        // The array of commands is inside the "commands" JSON object.
        // This line moves the parser pointer to this object.
        parser.nextToken();
        if (parser.nextToken() == XContentParser.Token.START_ARRAY) {
            commands = Command.parseToArray(parser);
        } else {
            log.error("Token does not match {}", parser.currentToken());
        }

        /// Commands expansion
        /// ==================
        /// Transforms the array of commands to orders.
        /// While commands can be targeted to groups of agents, orders are targeted to individual
        // agents.
        /// Given a group of agents A with N agents, a total of N orders are generated. One for each
        // agent.
        List<Agent> agentList =new ArrayList<>();
        Documents documents = new Documents();
        for (Command command : commands) {
            log.info("Command {}", command);
            log.info("[GROUP] Target id {}", command.getTarget().getId());
            if (Objects.equals(command.getTarget().getType(), "group")){

                // Build the search query
                SearchRequest searchRequest = new SearchRequest(".agents");
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("agent.id", command.getTarget().getId()));
                searchSourceBuilder.query(boolQuery);
                searchRequest.source(searchSourceBuilder);

                // Create the listener for the async search request
                client.search(searchRequest,  new ActionListener<SearchResponse>() {
                    @Override
                    public void onResponse(SearchResponse searchResponse) {
                        // Process the search response
                        SearchHits hits = searchResponse.getHits();
                        for (SearchHit hit : hits) {
                            final Map<String, Object> agentMap = getNestedObject(
                                                                    hit.getSourceAsMap(),
                                                                    "agent",
                                                                    Map.class);
                            if (agentMap != null) {
                                // log.info("[GROUP] Agent map {}", agentMap.get("groups"));
                                Agent agent = new Agent((List<String>) agentMap.get("groups"));
                                log.info("[GROUP] Agent instance {}", agent);
                                agentList.add(agent);
                            }
                        }
//                        log.info("[GROUP] Search response: {}", searchResponse.toString());
                        log.info("[GROUP] Search finished");
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("[GROUP] Search failed", e);
                    }
                });
            } else if (Objects.equals(command.getTarget().getType(), "agent")) {

                // Build the search query
                SearchRequest searchRequest = new SearchRequest(".agents");
                SearchSourceBuilder searchSourceBuilder = new SearchSourceBuilder();
                BoolQueryBuilder boolQuery = QueryBuilders.boolQuery()
                        .must(QueryBuilders.termQuery("agent.groups", command.getTarget().getId()));
                searchSourceBuilder.query(boolQuery);
                searchRequest.source(searchSourceBuilder);

                // Create the listener for the async search request
                client.search(searchRequest,  new ActionListener<SearchResponse>() {
                    @Override
                    public void onResponse(SearchResponse searchResponse) {
                        // Process the search response
                        SearchHits hits = searchResponse.getHits();
                        for (SearchHit hit : hits) {
                            final Map<String, Object> agentMap = getNestedObject(
                                    hit.getSourceAsMap(),
                                    "agent",
                                    Map.class);
                            if (agentMap != null) {
                                // log.info("[GROUP] Agent map {}", agentMap.get("groups"));
                                Agent agent = new Agent((List<String>) agentMap.get("groups"));
                                agentList.add(agent);
                                log.info("[GROUP] Agent instance {}", agent);
                            }
                        }
//                        log.info("[GROUP] Search response: {}", searchResponse.toString());
                        log.info("[GROUP] Search finished");
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("[GROUP] Search failed", e);
                    }
                });
            }
            for (Agent agent : agentList) {
                Document document = new Document(agent, command);
                documents.addDocument(document);
            }
        }

        /// Orders indexing
        /// ==================
        /// The orders are inserted into the index.
        CompletableFuture<RestStatus> bulkRequestFuture =
                this.commandIndex.asyncBulkCreate(documents.getDocuments());

        /// Send response
        /// ==================
        /// Reply to the request.
        return channel -> {
            bulkRequestFuture
                    .thenAccept(
                            restStatus -> {
                                try (XContentBuilder builder = channel.newBuilder()) {
                                    builder.startObject();
                                    builder.field("_index", CommandManagerPlugin.INDEX_NAME);
                                    documents.toXContent(builder, ToXContent.EMPTY_PARAMS);
                                    builder.field("result", restStatus.name());
                                    builder.endObject();
                                    channel.sendResponse(
                                            new BytesRestResponse(restStatus, builder));
                                } catch (IOException e) {
                                    log.error(
                                            "Error preparing response to [{}] request with id [{}] due to {}",
                                            request.method().name(),
                                            request.getRequestId(),
                                            e.getMessage());
                                }
                            })
                    .exceptionally(
                            e -> {
                                channel.sendResponse(
                                        new BytesRestResponse(
                                                RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
                                return null;
                            });
        };
    }
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
}
