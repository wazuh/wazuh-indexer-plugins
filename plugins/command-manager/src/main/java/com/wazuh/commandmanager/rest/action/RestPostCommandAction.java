package com.wazuh.commandmanager.rest.action;

import com.wazuh.commandmanager.CommandManagerPlugin;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActiveShardCount;
import org.opensearch.client.node.NodeClient;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.index.VersionType;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.rest.action.RestActions;
import org.opensearch.rest.action.RestStatusToXContentListener;

import java.io.IOException;
import java.util.*;

import static org.opensearch.rest.RestRequest.Method.POST;

public class RestPostCommandAction extends BaseRestHandler {

    public static final String POST_COMMAND_ACTION_REQUEST_DETAILS = "post_command_action_request_details";

    private final Logger logger = LogManager.getLogger(RestPostCommandAction.class);

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
                                "%s/%s/{%s}",
                                CommandManagerPlugin.COMMAND_MANAGER_BASE_URI,
                                "create",
                                "id"
                        )
                )
        );
    }

    @Override
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) {
        IndexRequest indexRequest = new IndexRequest(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
        indexRequest.id(request.param("id"));
        indexRequest.routing(request.param("routing"));
        indexRequest.setPipeline(request.param("pipeline"));
        indexRequest.source(request.requiredContent(), request.getMediaType());
        indexRequest.timeout(request.paramAsTime("timeout", IndexRequest.DEFAULT_TIMEOUT));
        indexRequest.setRefreshPolicy(request.param("refresh"));
        indexRequest.version(RestActions.parseVersion(request));
        indexRequest.versionType(VersionType.fromString(request.param("version_type"), indexRequest.versionType()));
        indexRequest.setIfSeqNo(request.paramAsLong("if_seq_no", indexRequest.ifSeqNo()));
        indexRequest.setIfPrimaryTerm(request.paramAsLong("if_primary_term", indexRequest.ifPrimaryTerm()));
        indexRequest.setRequireAlias(request.paramAsBoolean(DocWriteRequest.REQUIRE_ALIAS, indexRequest.isRequireAlias()));

        // Source. One of [Users/Services (via Management API), Engine (via Management API), Content manager (directly)]
        request.params().putIfAbsent("source", "engine");
        // User. The user that originated the request. This user may represent a Management API or Indexer API user depending on the source.
        request.params().putIfAbsent("user", "admin");
        // Target. Cluster name destination.
        request.params().putIfAbsent("target", "wazuh-cluster");
        // Type. One of [Agent groups, Agent, Server cluster]
        request.params().putIfAbsent("type", "agent");
        // Timeout. Number of seconds to wait for the command to be executed.
        request.params().putIfAbsent("timeout", "120");
        // Action
        Map<String, String> actionField = new HashMap<>();
        // Type. One of [Agent groups, Agent, Server cluster]
        actionField.put("type", "agent");
        // Params. Additional parameters for the action.
        actionField.put("params", "--help");
        // Version. Version of the action.
        actionField.put("version", "1.0");

        // Get the action object into a json string
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject();
            for (Map.Entry<String, String> entry : actionField.entrySet()) {
                builder.field(entry.getKey(), entry.getValue());
            }
            builder.endObject();
            String actionFieldJson = builder.toString();
            request.params().put("action", actionFieldJson);
        } catch (IOException e) {
            logger.error(e);
        }

        String sOpType = request.param("op_type");
        String waitForActiveShards = request.param("wait_for_active_shards");
        if (waitForActiveShards != null) {
            indexRequest.waitForActiveShards(ActiveShardCount.parseString(waitForActiveShards));
        }
        if (sOpType != null) {
            indexRequest.opType(sOpType);
        }

        return channel -> client.index(
                indexRequest,
                new RestStatusToXContentListener<>(channel, r -> r.getLocation(indexRequest.routing()))
        );
    }
}
