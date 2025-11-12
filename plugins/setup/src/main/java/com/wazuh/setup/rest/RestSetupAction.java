// src/main/java/com/wazuh/setup/rest/RestSetupAction.java
package com.wazuh.setup.rest;

import org.opensearch.rest.RestRequest;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import java.util.List;

import static org.opensearch.rest.RestRequest.Method.POST;

public class RestSetupAction extends BaseWazuhRestHandler {

    public RestSetupAction(ThreadPool threadPool) {
        super(threadPool);
    }

    @Override
    public String getName() {
        return "wazuh_setup_action";
    }

    @Override
    public List<Route> routes() {
        return List.of(
            new Route(POST, "/_plugins/_wazuh/setup")
        );
    }

    @Override
    protected String getEndpoint() {
        return "setup";  // Results in "restapi:admin/wazuh/setup"
    }

    @Override
    protected RestChannelConsumer handleApiRequest(
        RestRequest request,
        NodeClient client
    ) throws Exception {
        return channel -> {
            try {
                // Your actual setup logic here
                boolean setupComplete = performSetup();

                XContentBuilder builder = channel.newBuilder();
                builder.startObject();
                builder.field("status", "success");
                builder.field("setup_complete", setupComplete);
                builder.endObject();

                channel.sendResponse(
                    new BytesRestResponse(RestStatus.OK, builder)
                );
            } catch (Exception e) {
                channel.sendResponse(
                    new BytesRestResponse(
                        RestStatus.INTERNAL_SERVER_ERROR,
                        e.getMessage()
                    )
                );
            }
        };
    }

    private boolean performSetup() {
        // Your setup logic
        return true;
    }
}
