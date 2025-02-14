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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.model.*;
import com.wazuh.commandmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/** Handles HTTP requests to the POST the Commands API endpoint. */
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
                new Route(POST, String.format(Locale.ROOT, "%s", PluginSettings.getApiCommandsEndpoint())));
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client)
            throws IOException {
        switch (request.method()) {
            case POST:
                return handlePost(request, client);
            default:
                throw new IllegalArgumentException("Unsupported HTTP method " + request.method().name());
        }
    }

    /**
     * Handles a POST HTTP request.
     *
     * @param request POST HTTP request
     * @param client NodeClient instance
     * @return a response to the request as BytesRestResponse.
     * @throws IOException thrown by the XContentParser methods.
     */
    private RestChannelConsumer handlePost(RestRequest request, final NodeClient client)
            throws IOException {
        log.info(
                "Received {} {} request id [{}] from host [{}]",
                request.method().name(),
                request.uri(),
                request.getRequestId(),
                request.header("Host"));
        // Request validation
        if (!request.hasContent()) {
            return channel -> {
                channel.sendResponse(
                        new BytesRestResponse(RestStatus.BAD_REQUEST, "Body content is required"));
            };
        }
        List<Command> commands = Command.parse(request);
        // Validate commands are not empty
        if (commands.isEmpty()) {
            return channel -> {
                channel.sendResponse(
                        new BytesRestResponse(RestStatus.BAD_REQUEST, "No commands provided."));
            };
        }

        /// Commands expansion
        /// ==================
        /// Transforms the array of commands to orders.
        /// While commands can be targeted to groups of agents, orders are targeted to individual
        // agents.
        /// Given a group of agents A with N agents, a total of N orders are generated. One for each
        // agent.
        Orders orders = Orders.fromCommands(client, commands);
        // Validate that the orders are not empty
        if (orders.get().isEmpty()) {
            return channel -> {
                channel.sendResponse(
                        new BytesRestResponse(
                                RestStatus.BAD_REQUEST, "Cannot generate orders. Invalid agent IDs or groups."));
            };
        }

        // Orders indexing
        CompletableFuture<RestStatus> bulkRequestFuture =
                this.commandIndex.asyncBulkCreate(orders.get());

        // Send response
        return channel -> {
            bulkRequestFuture
                    .thenAccept(
                            restStatus -> {
                                try (XContentBuilder builder = channel.newBuilder()) {
                                    builder.startObject();
                                    builder.field("_index", PluginSettings.getIndexName());
                                    orders.toXContent(builder, ToXContent.EMPTY_PARAMS);
                                    builder.field("result", restStatus.name());
                                    builder.endObject();
                                    channel.sendResponse(new BytesRestResponse(restStatus, builder));
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
                                        new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
                                return null;
                            });
        };
    }
}
