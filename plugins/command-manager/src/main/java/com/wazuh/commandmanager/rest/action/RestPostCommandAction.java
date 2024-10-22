/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.rest.action;

import com.wazuh.commandmanager.CommandManagerJobParameter;
import com.wazuh.commandmanager.CommandManagerJobRunner;
import com.wazuh.commandmanager.CommandManagerPlugin;
import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.model.Document;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.jobscheduler.spi.schedule.IntervalSchedule;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.RestResponse;

import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
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
    private static final Logger logger = LogManager.getLogger(RestPostCommandAction.class);
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
                POST,
                String.format(
                    Locale.ROOT,
                    "%s",
                    CommandManagerPlugin.COMMAND_MANAGER_BASE_URI
                )
            ),
            new Route(
                POST,
                String.format(
                    Locale.ROOT,
                    "%s",
                    CommandManagerPlugin.COMMAND_MANAGER_SCHEDULER_URI
                )
            )
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(
            final RestRequest restRequest,
            final NodeClient client
    ) throws IOException {
        // Get request details
        switch(restRequest.path()) {
            case CommandManagerPlugin.COMMAND_MANAGER_BASE_URI:
                XContentParser parser = restRequest.contentParser();
                ensureExpectedToken(XContentParser.Token.START_OBJECT, parser.nextToken(), parser);
                Document document = Document.parse(parser);
                // Send response
                return channel -> {
                    this.commandIndex.asyncCreate(document)
                        .thenAccept(restStatus -> {
                            try (XContentBuilder builder = channel.newBuilder()) {
                                builder.startObject();
                                builder.field("_index", CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
                                builder.field("_id", document.getId());
                                builder.field("result", restStatus.name());
                                builder.endObject();
                                channel.sendResponse(new BytesRestResponse(restStatus, builder));
                            } catch (Exception e) {
                                logger.error("Error indexing command: ", e);
                            }
                        }).exceptionally(e -> {
                            channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
                            return null;
                        });
                };
            case CommandManagerPlugin.COMMAND_MANAGER_SCHEDULER_URI:
                return createJob(client);
        }
        return null;
    }

    private static RestChannelConsumer createJob(NodeClient client) throws IOException {
        String id = "test-id";
        String indexName = "test-index";
        String jobName = "command_manager_scheduler_extension";
        String interval = "1";
        String lockDurationSecondsString = "1";
        Long lockDurationSeconds = Long.parseLong(lockDurationSecondsString);

        CommandManagerJobParameter jobParameter = new CommandManagerJobParameter(
            jobName,
            indexName,
            new IntervalSchedule(Instant.now(), Integer.parseInt(interval), ChronoUnit.MINUTES),
            lockDurationSeconds
        );

        IndexRequest indexRequest = new IndexRequest().index(CommandManagerPlugin.JOB_INDEX_NAME)
            .id(id)
            .source(jobParameter.toXContent(JsonXContent.contentBuilder(), null))
            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        return restChannel -> {
            client.index(indexRequest, new ActionListener<>() {
                @Override
                public void onResponse(IndexResponse indexResponse) {
                    try {
                        RestResponse restResponse = new BytesRestResponse(
                            RestStatus.OK,
                            indexResponse.toXContent(JsonXContent.contentBuilder(), null)
                        );
                        restChannel.sendResponse(restResponse);
                    } catch (IOException e) {
                        restChannel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
                    }
                    logger.info("Scheduled job {}", jobName);
                }

                @Override
                public void onFailure(Exception e) {
                    restChannel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
                    logger.error("Failed to schedule job {}, exception: {}", jobName, e.getMessage());
                }
            });
        };
    }
}
