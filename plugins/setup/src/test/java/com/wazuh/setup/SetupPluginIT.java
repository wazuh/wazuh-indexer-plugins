/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.setup;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.apache.http.ParseException;
import org.apache.http.util.EntityUtils;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequest;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.cluster.node.info.NodeInfo;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.opensearch.action.admin.cluster.node.info.PluginsAndModules;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.plugins.Plugin;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Assert;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsString;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class SetupPluginIT extends OpenSearchIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Collections.singletonList(SetupPlugin.class);
    }

    public void testPluginInstalled() throws IOException, ParseException {
        Response response = getRestClient().performRequest(new Request("GET", "/_cat/plugins"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("response body: {}", body);
        assertThat(body, containsString("wazuh-indexer-setup"));
    }

    public void testPluginsAreInstalled() {
        ClusterHealthRequest request = new ClusterHealthRequest();
        ClusterHealthResponse response =
                OpenSearchIntegTestCase.client().admin().cluster().health(request).actionGet();
        Assert.assertEquals(ClusterHealthStatus.GREEN, response.getStatus());

        NodesInfoRequest nodesInfoRequest = new NodesInfoRequest();
        nodesInfoRequest.addMetric(NodesInfoRequest.Metric.PLUGINS.metricName());
        NodesInfoResponse nodesInfoResponse =
                OpenSearchIntegTestCase.client()
                        .admin()
                        .cluster()
                        .nodesInfo(nodesInfoRequest)
                        .actionGet();
        List<PluginInfo> pluginInfos =
                nodesInfoResponse.getNodes().stream()
                        .flatMap(
                                (Function<NodeInfo, Stream<PluginInfo>>)
                                        nodeInfo ->
                                                nodeInfo
                                                        .getInfo(PluginsAndModules.class)
                                                        .getPluginInfos()
                                                        .stream())
                        .collect(Collectors.toList());
        Assert.assertTrue(
                pluginInfos.stream()
                        .anyMatch(
                                pluginInfo -> pluginInfo.getName().equals("wazuh-indexer-setup")));
    }
}
