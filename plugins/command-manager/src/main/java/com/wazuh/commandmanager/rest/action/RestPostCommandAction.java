/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.rest.action;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.model.Command;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.Randomness;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.Collections;
import java.util.List;
import java.util.Locale;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.opensearch.rest.RestRequest.Method.POST;

/**
 * Handles HTTP requests to the POST
 * {@value com.wazuh.commandmanager.CommandManagerPlugin#COMMAND_MANAGER_BASE_URI}
 * endpoint.
 */
public class RestPostCommandAction extends BaseRestHandler {

    public static final String POST_COMMAND_ACTION_REQUEST_DETAILS = "post_command_action_request_details";

    private final Logger logger = LogManager.getLogger(RestPostCommandAction.class);

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
        return Collections.singletonList(
                new Route(
                        POST,
                        String.format(
                                Locale.ROOT,
                                "%s",
                                CommandManagerPlugin.COMMAND_MANAGER_BASE_URI
                        )
                )
        );
    }

    /**
     * Generates a random ID as string on range 0 to 10.
     *
     * @return random int as string
     * TODO To be removed in future iterations
     */
    private String getRandomId() {
        return "" + Randomness.get().nextInt();
    }

    @Override
    protected RestChannelConsumer prepareRequest(
            final RestRequest restRequest,
            final NodeClient client
    ) throws IOException {
        // Get request details
        XContentParser parser = restRequest.contentParser();
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        // Placeholders. These IDs will be generated properly on next iterations.
        String requestId = getRandomId();
        String orderId = getRandomId();
        Command command = Command.parse(requestId, orderId, parser);

        // Persist command
        IndexResponse indexResponse = this.commandIndex.create(command).actionGet();

        // Send response
        return channel -> {
            try (XContentBuilder builder = channel.newBuilder()) {
                builder.startObject();
                builder.field("command", command.getId());
                builder.endObject();
                channel.sendResponse(new BytesRestResponse(indexResponse.status(), builder));
            }
        };
    }
}
