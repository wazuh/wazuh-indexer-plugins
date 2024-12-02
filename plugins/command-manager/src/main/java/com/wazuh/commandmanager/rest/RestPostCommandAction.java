/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.rest;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.model.Agent;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.model.Document;
import com.wazuh.commandmanager.model.Documents;
import com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.opensearch.rest.RestRequest.Method.POST;
import static com.wazuh.commandmanager.utils.httpclient.HttpRestClientDemo.SECURITY_USER_AUTHENTICATE;

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
                        POST, String.format(Locale.ROOT, "%s", CommandManagerPlugin.COMMANDS_URI)),
                new Route(POST, String.format(Locale.ROOT, "%s", SECURITY_USER_AUTHENTICATE)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client)
            throws IOException {
        switch (request.method()) {
            case POST:
                return handlePost(request);
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
    private RestChannelConsumer handlePost(RestRequest request) throws IOException {
        log.info(
                "Received {} {} request id [{}] from host [{}]",
                request.method().name(),
                request.uri(),
                request.getRequestId(),
                request.header("Host"));

        // Get request details
        if (!request.hasContent()) {
            // Bad request if body doesn't exist
            return channel -> {
                channel.sendResponse(
                        new BytesRestResponse(RestStatus.BAD_REQUEST, "Body content is required"));
            };
        }

        XContentParser parser = request.contentParser();
        List<Command> commands = new ArrayList<>();
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
        parser.nextToken();
        if (parser.nextToken() == XContentParser.Token.START_ARRAY) {
            commands = Command.parseToArray(parser);
        } else {
            log.error("Token does not match {}", parser.currentToken());
        }

        Documents documents = new Documents();
        for (Command command : commands) {
            Document document =
                    new Document(
                            new Agent(List.of("groups000")), // TODO read agent from .agents index
                            command);
            documents.addDocument(document);

            // Commands delivery to the Management API.
            // Note: needs to be decoupled from the Rest handler (job scheduler task).
            try {
                String payload =
                        document.toXContent(XContentFactory.jsonBuilder(), ToXContent.EMPTY_PARAMS)
                                .toString();
                SimpleHttpResponse response =
                        HttpRestClientDemo.runWithResponse(payload, document.getId());
                log.info("Received response to POST request with code [{}]", response.getCode());
                log.info("Raw response:\n{}", response.getBodyText());
            } catch (Exception e) {
                log.error("Error reading response: {}", e.getMessage());
            }
        }

        // Send response
        return channel -> {
            this.commandIndex
                    .asyncBulkCreate(documents.getDocuments())
                    .thenAccept(
                            restStatus -> {
                                try (XContentBuilder builder = channel.newBuilder()) {
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
}
