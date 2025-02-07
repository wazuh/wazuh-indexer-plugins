package com.wazuh.contentmanager.rest;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.Document;
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

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.opensearch.rest.RestRequest.Method.GET;
import static org.opensearch.rest.RestRequest.Method.POST;

//JUST FOR TESTING PURPOSE
public class RestPostContentAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestPostContentAction.class);

    public static final String POST_CONTENT_ACTION_REQUEST_DETAILS = "post_content_action_request_details";
    private final ContextIndex contextIndex;

    public RestPostContentAction(ContextIndex contextIndex) {
        this.contextIndex = contextIndex;
    }

    @Override
    public String getName() {
        return POST_CONTENT_ACTION_REQUEST_DETAILS;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new Route(
                        POST,
                        String.format(
                                Locale.ROOT,
                                "%s",
                                ContentManagerPlugin.CONTEXT_URI
                        )
                ),
                new Route(GET, String.format(Locale.ROOT,
                        "%s",
                        ContentManagerPlugin.CONTEXT_URI))
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest restRequest, NodeClient nodeClient) throws IOException {
        switch (restRequest.method()) {
            case POST:
                return handlePost(restRequest);
            case GET:
               // return handleGet(restRequest);
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
        log.info(
                "Received {} {} request id [{}] from host [{}]",
                request.method().name(),
                request.uri(),
                request.getRequestId(),
                request.header("Host")
        );
        // Get request details
        XContentParser parser = request.contentParser();
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        Document document = Document.parse(parser);

        // Send response
        return channel -> {
            this.contextIndex.indexDocument(document)
                    .thenAccept(restStatus -> {
                        try (XContentBuilder builder = channel.newBuilder()) {
                            builder.startObject();
                            builder.field("_index", ContextIndex.INDEX_NAME);
                            builder.field("result", restStatus.name());
                            builder.endObject();
                            channel.sendResponse(new BytesRestResponse(restStatus, builder));
                        } catch (IOException e) {
                            log.error("Error preparing response to [{}] request with id [{}] due to {}",
                                    request.method().name(),
                                    request.getRequestId(),
                                    e.getMessage()
                            );
                        }
                    }).exceptionally(e -> {
                        channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
                        return null;
                    });
        };
    }
}
