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
import org.opensearch.core.xcontent.XContentParser;
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
    protected RestChannelConsumer prepareRequest(final RestRequest request, final NodeClient client) throws IOException {
        IndexRequest indexRequest = new IndexRequest(CommandManagerPlugin.COMMAND_MANAGER_INDEX_NAME);
        // ID. Document ID. Generated combining the Order ID and the Command Request ID.
        indexRequest.id(request.param("id"));
        indexRequest.routing(request.param("routing"));
        indexRequest.setPipeline(request.param("pipeline"));
        indexRequest.timeout(request.paramAsTime("timeout", IndexRequest.DEFAULT_TIMEOUT));
        indexRequest.setRefreshPolicy(request.param("refresh"));
        indexRequest.version(RestActions.parseVersion(request));
        indexRequest.versionType(VersionType.fromString(request.param("version_type"), indexRequest.versionType()));
        indexRequest.setIfSeqNo(request.paramAsLong("if_seq_no", indexRequest.ifSeqNo()));
        indexRequest.setIfPrimaryTerm(request.paramAsLong("if_primary_term", indexRequest.ifPrimaryTerm()));
        indexRequest.setRequireAlias(request.paramAsBoolean(DocWriteRequest.REQUIRE_ALIAS, indexRequest.isRequireAlias()));

        Map<String, Object> requestBodyMap;

        try ( XContentParser requestBodyXContent = request.contentParser() ) {
            requestBodyMap = requestBodyXContent.map();
        } catch (IOException e) {
            throw new RuntimeException(e);
        }

        // Source. One of [Users/Services (via Management API), Engine (via Management API), Content manager (directly)]
        requestBodyMap.putIfAbsent("source", "engine");
        // User. The user that originated the request. This user may represent a Management API or Indexer API user depending on the source.
        requestBodyMap.putIfAbsent("user", "admin");
        // Target. Cluster name destination.
        requestBodyMap.putIfAbsent("target", "wazuh-cluster");
        // Type. One of [Agent groups, Agent, Server cluster]
        requestBodyMap.putIfAbsent("type", "agent");
        // Timeout. Number of seconds to wait for the command to be executed.
        requestBodyMap.putIfAbsent("timeout", "120");
        // Command Request ID. Unique identifier generated by the Command Manager. Auto-incremental.
        //assert requestBodyMap.containsKey("request_id"): "No request_id provided";
        // Order ID. Unique identifier generated by the Command Manager. Auto-incremental within the same Command Request ID.
        //assert requestBodyMap.containsKey("order_id"): "No order_id provided";


        // Action object
        Map<String, String> actionField = new HashMap<>();
        // Type. One of [Agent groups, Agent, Server cluster]
        actionField.put("type", "agent");
        // Params. Additional parameters for the action.
        actionField.put("params", "--help");
        // Version. Version of the action.
        actionField.put("version", "1.0");

        // Get the Action object into a json string
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject();
            for (Map.Entry<String, String> entry : actionField.entrySet()) {
                builder.field(entry.getKey(), entry.getValue());
            }
            builder.endObject();
            String actionFieldJson = builder.toString();
            requestBodyMap.putIfAbsent("action", actionFieldJson);
        } catch (IOException e) {
            logger.error(e);
        }

        // Result object
        Map<String, String> resultField = new HashMap<>();
        // Code. Result code
        resultField.put("code", "");
        // Message. Description of the result
        resultField.put("message", "");
        // Data. Additional data
        resultField.put("data", "");

        // Get the Result object into a json string
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            builder.startObject();
            for (Map.Entry<String, String> entry : resultField.entrySet()) {
                builder.field(entry.getKey(), entry.getValue());
            }
            builder.endObject();
            String resultFieldJson = builder.toString();
            requestBodyMap.putIfAbsent("result", resultFieldJson);
        } catch (IOException e) {
            logger.error(e);
        }


        indexRequest.source(requestBodyMap, request.getMediaType());
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
