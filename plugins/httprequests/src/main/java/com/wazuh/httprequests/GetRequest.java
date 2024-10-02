/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */

package com.wazuh.httprequests;

import org.opensearch.client.node.NodeClient;
import org.opensearch.common.lifecycle.Lifecycle;
import org.opensearch.common.lifecycle.LifecycleComponent;
import org.opensearch.common.lifecycle.LifecycleListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;

import java.io.IOException;
import java.util.List;

import static org.opensearch.rest.RestRequest.Method.GET;

public class GetRequest extends BaseRestHandler implements LifecycleComponent {

    AsyncHttpService asyncHttpService;

    public GetRequest(){
    }

    @Override
    public String getName() {
        return "http-request-get";
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(GET, HttpRequestsPlugin.BASE_URI));
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) throws IOException {
        asyncHttpService = new AsyncHttpService();

        return channel -> {
            this.asyncHttpService.prepareAsyncRequest();
            this.asyncHttpService.performAsyncRequest()
                .thenAccept(
                    response -> {
                        channel.sendResponse(new BytesRestResponse(RestStatus.OK, response));
                    }
                ).exceptionally(
                    e -> {
                        channel.sendResponse(new BytesRestResponse(RestStatus.INTERNAL_SERVER_ERROR, e.getMessage()));
                        return null;
                    }
                );
        };

    }

    @Override
    public Lifecycle.State lifecycleState() {
        return null;
    }

    @Override
    public void addLifecycleListener(LifecycleListener lifecycleListener) {

    }

    @Override
    public void removeLifecycleListener(LifecycleListener lifecycleListener) {

    }

    @Override
    public void start() {

    }

    @Override
    public void stop() {
        this.asyncHttpService.close();
    }

    @Override
    public void close() {
        this.asyncHttpService.close();
    }
}
