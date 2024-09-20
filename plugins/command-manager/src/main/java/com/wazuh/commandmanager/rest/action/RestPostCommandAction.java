package com.wazuh.commandmanager.rest.action;

import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.rest.request.PostCommandRequest;
import com.wazuh.commandmanager.utils.CommandManagerService;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import static org.opensearch.core.xcontent.XContentParserUtils.ensureExpectedToken;
import static org.opensearch.rest.RestRequest.Method.POST;

public class RestPostCommandAction extends BaseRestHandler {

    public static final String POST_COMMAND_ACTION_REQUEST_DETAILS = "post_command_action_request_details";

    private final Logger logger = LogManager.getLogger(RestPostCommandAction.class);

    public CommandManagerService commandManagerService;

    public RestPostCommandAction(final CommandManagerService commandManagerService) {
        this.commandManagerService = commandManagerService;
    }

    public String getName() {
        return POST_COMMAND_ACTION_REQUEST_DETAILS;
    }

    @Override
    public List<Route> routes() {
        return Collections.singletonList(
//            new Route(
//                POST,
//                String.format(
//                    Locale.ROOT,
//                    "%s",
//                    CommandManagerPlugin.COMMAND_MANAGER_BASE_URI
//                )
//            ),
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

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest restRequest, final NodeClient client) throws IOException {
        XContentParser parser = restRequest.contentParser();
        ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);

        PostCommandRequest postCommandRequest = PostCommandRequest.parse(parser);
        String commandOrderId = commandManagerService.generateRandomString(4);
        String commandRequestId = commandManagerService.generateRandomString(4);
        // The document ID is a concatenation of the orderId and the requestId
        String documentId = commandOrderId + commandRequestId;
        String commandSource = postCommandRequest.getCommandSource();
        String commandTarget = postCommandRequest.getCommandTarget();
        String commandTimeout = postCommandRequest.getCommandTimeout();
        String commandType = postCommandRequest.getCommandType();
        String commandUser = postCommandRequest.getCommandUser();
        Map<String,Object> commandAction = postCommandRequest.getCommandAction();
        Map<String,Object> commandResult = postCommandRequest.getCommandResult();

        CompletableFuture<String> inProgressFuture = new CompletableFuture<>();

        commandManagerService.processCommand(
            documentId,
            commandOrderId,
            commandRequestId,
            commandSource,
            commandTarget,
            commandTimeout,
            commandType,
            commandUser,
            commandAction,
            commandResult,
            new ActionListener<>() {
                @Override
                public void onResponse(String indexedDocumentId) {
                    // Set document Id
                    inProgressFuture.complete(indexedDocumentId);
                }

                @Override
                public void onFailure(Exception e) {
                    logger.info("could not process command", e);
                    inProgressFuture.completeExceptionally(e);
                }
            }
        );

        try {
            inProgressFuture.orTimeout(CommandManagerService.TIME_OUT_FOR_REQUEST, TimeUnit.SECONDS);
        } catch (CompletionException e) {
            if (e.getCause() instanceof TimeoutException) {
                logger.error("Get Command Details timed out ", e);
            }
            if (e.getCause() instanceof RuntimeException) {
                throw (RuntimeException) e.getCause();
            } else if (e.getCause() instanceof Error) {
                throw (Error) e.getCause();
            } else {
                throw new RuntimeException(e.getCause());
            }
        }

        return channel -> {
            String commandDetailsResponseHolder = null;
            try {
                commandDetailsResponseHolder = inProgressFuture.get();
            } catch (Exception e) {
                logger.error("Exception occured in get command details ", e);
            }
            XContentBuilder builder = channel.newBuilder();
            RestStatus restStatus = RestStatus.OK;
            String restResponseString = commandDetailsResponseHolder != null ? "success" : "failed";
            BytesRestResponse bytesRestResponse;
            try {
                builder.startObject();
                builder.field("response", restResponseString);
                if (restResponseString.equals("success")) {
                    builder.field(PostCommandRequest.DOCUMENT_ID, commandDetailsResponseHolder);
                } else {
                    restStatus = RestStatus.INTERNAL_SERVER_ERROR;
                }
                builder.endObject();
                bytesRestResponse = new BytesRestResponse(restStatus, builder);
            } finally {
                builder.close();
            }

            channel.sendResponse(bytesRestResponse);
        };
    }
}
