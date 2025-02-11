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
package com.wazuh.contentmanager.rest;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.GenericDocument;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.opensearch.rest.RestRequest.Method.*;

public class RestPostContentManager extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostContentManager.class);

    public static final String POST_CONTENT_MANAGER_REQUEST = "post_content_manager_request";
    private final ContentIndex contentIndex;

    public RestPostContentManager(ContentIndex contentIndex) {
        this.contentIndex = contentIndex;
    }

    @Override
    public String getName() {
        return POST_CONTENT_MANAGER_REQUEST;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(
                        PATCH,
                        String.format(
                                Locale.ROOT, "%s", ContentManagerPlugin.CONTENT_MANAGER_BASE_URI)),
                new Route(
                        POST,
                        String.format(
                                Locale.ROOT, "%s", ContentManagerPlugin.CONTENT_MANAGER_BASE_URI)));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest restRequest, NodeClient nodeClient)
            throws IOException {
        log.info("prepareRequest() executed");
        switch (restRequest.method()) {
            case POST:
                return handlePost(restRequest);
            default:
                throw new IllegalArgumentException(
                        "Unsupported HTTP method " + restRequest.method().name());
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
        if (!this.contentIndex.indexExists()) {
            this.contentIndex.createIndex();
        }

        log.info(
                "Received {} {} request id [{}] from host [{}]",
                request.method().name(),
                request.uri(),
                request.getRequestId(),
                request.header("Host"));
        // Get request details
        XContentParser parser = request.contentParser();
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        GenericDocument genericDocument = GenericDocument.parse(parser);

        // Send response
        return channel -> {
            this.contentIndex
                    // another id to test
                    .indexDocument(genericDocument)
                    .thenAccept(
                            (RestStatus restStatus) -> {
                                try (XContentBuilder builder = channel.newBuilder()) {
                                    builder.startObject();
                                    builder.field("_index", ContextIndex.INDEX_NAME);
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
