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
package com.wazuh.setup;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
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
import java.util.List;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests for the SetupPlugin. This class checks if the plugin is installed and verifies
 * the presence of required plugins.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class SetupPluginIT extends OpenSearchIntegTestCase {

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return List.of(SetupPlugin.class);
    }

    /**
     * Test to verify that the Wazuh Indexer Setup plugin is installed.
     *
     * @throws IOException Thrown if there is an issue with the HTTP request.
     * @throws ParseException Thrown if there is an issue parsing the response.
     */
    public void testPluginInstalled() throws IOException, ParseException {
        Response response = getRestClient().performRequest(new Request("GET", "/_cat/plugins"));
        String body = EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8);

        logger.info("response body: {}", body);
        assertThat(body, containsString("wazuh-indexer-setup"));
    }

    /** Test to verify that the Wazuh Indexer Setup plugin is installed and the cluster is healthy. */
    public void testPluginsAreInstalled() {
        ClusterHealthRequest request = new ClusterHealthRequest();
        ClusterHealthResponse response =
                OpenSearchIntegTestCase.client().admin().cluster().health(request).actionGet();
        Assert.assertEquals(ClusterHealthStatus.GREEN, response.getStatus());

        NodesInfoRequest nodesInfoRequest = new NodesInfoRequest();
        nodesInfoRequest.addMetric(NodesInfoRequest.Metric.PLUGINS.metricName());
        NodesInfoResponse nodesInfoResponse =
                OpenSearchIntegTestCase.client().admin().cluster().nodesInfo(nodesInfoRequest).actionGet();
        List<PluginInfo> pluginInfos =
                nodesInfoResponse.getNodes().stream()
                        .flatMap(
                                (Function<NodeInfo, Stream<PluginInfo>>)
                                        nodeInfo -> nodeInfo.getInfo(PluginsAndModules.class).getPluginInfos().stream())
                        .toList();
        Assert.assertTrue(
                pluginInfos.stream()
                        .anyMatch(pluginInfo -> pluginInfo.getName().equals("wazuh-indexer-setup")));
    }

    /** Test to verify that the ISM plugin is installed and the cluster is healthy. */
    public void testISMPluginInstalled() {
        ClusterHealthRequest request = new ClusterHealthRequest();
        ClusterHealthResponse response =
                OpenSearchIntegTestCase.client().admin().cluster().health(request).actionGet();
        Assert.assertEquals(ClusterHealthStatus.GREEN, response.getStatus());

        NodesInfoRequest nodesInfoRequest = new NodesInfoRequest();
        nodesInfoRequest.addMetric(NodesInfoRequest.Metric.PLUGINS.metricName());
        NodesInfoResponse nodesInfoResponse =
                OpenSearchIntegTestCase.client().admin().cluster().nodesInfo(nodesInfoRequest).actionGet();
        List<PluginInfo> pluginInfos =
                nodesInfoResponse.getNodes().stream()
                        .flatMap(
                                (Function<NodeInfo, Stream<PluginInfo>>)
                                        nodeInfo -> nodeInfo.getInfo(PluginsAndModules.class).getPluginInfos().stream())
                        .toList();
        Assert.assertTrue(
                pluginInfos.stream()
                        .anyMatch(pluginInfo -> pluginInfo.getName().equals("opensearch-index-management")));
    }
}
