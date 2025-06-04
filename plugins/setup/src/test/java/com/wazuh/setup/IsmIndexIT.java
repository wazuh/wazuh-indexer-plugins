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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.test.OpenSearchIntegTestCase;

/** Test indexing policies */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ISMIndexIT extends OpenSearchIntegTestCase {

    // @Override
    // protected Collection<Class<? extends Plugin>> nodePlugins() {
    //    return Collections.singletonList(SetupPlugin.class);
    // }

    private static final Logger log = LogManager.getLogger(ISMIndexIT.class);

    /// ** Creates an index */
    // private void putTestIndex() {
    //    Map<String, Object> template = null;
    //    CreateIndexResponse response = null;
    //    try (Client client = client()) {
    //        template = IndexTemplateUtils.fromFile(TEST_TEMPLATE + ".json");
    //        CreateIndexRequest request =
    //                new CreateIndexRequest(TEST_INDEX)
    //                        .mapping(IndexTemplateUtils.get(template, "mappings"))
    //                        .settings(IndexTemplateUtils.get(template, "settings"))
    //                        .alias(new Alias(TEST_ALIAS).writeIndex(true));
    //        PlainActionFuture<CreateIndexResponse> future = new PlainActionFuture<>();
    //        client.admin().indices().create(request, future);
    //        response = future.get(5, TimeUnit.SECONDS);
    //    } catch (IOException | InterruptedException | TimeoutException | ExecutionException e) {
    //        log.error("Failed to retrieve {} file: {}", TEST_TEMPLATE, e.getMessage());
    //    }
    //    assert response != null;
    //    assertTrue(response.isAcknowledged());
    //    assertTrue(iSMIndexExists(TEST_INDEX));
    // }

    /// ** Test that alias points to the newly created index */
    // public void testAlias() {
    //    putTestIndex();
    //    GetAliasesResponse getAliasesResponse = null;
    //    try (Client client = client()) {
    //        GetAliasesRequest getAliasesRequest = new GetAliasesRequest().indices(TEST_INDEX);
    //        PlainActionFuture<GetAliasesResponse> future = new PlainActionFuture<>();
    //        client.admin().indices().getAliases(getAliasesRequest, future);
    //        getAliasesResponse = future.get(5, TimeUnit.SECONDS);
    //    } catch (ExecutionException | InterruptedException | TimeoutException e) {
    //        log.error("Failed to retrieve {} alias: {}", TEST_ALIAS, e.getMessage());
    //    }
    //    assert getAliasesResponse != null;
    //    // Check that the TEST_INDEX is set as write_index of the TEST_ALIAS
    //    assertTrue(getAliasesResponse.getAliases().get(TEST_INDEX).get(0).writeIndex());
    // }

    // public void testPluginsAreInstalled() {
    //    NodesInfoRequest nodesInfoRequest = new NodesInfoRequest();
    //    nodesInfoRequest.addMetric(NodesInfoRequest.Metric.PLUGINS.metricName());
    //    NodesInfoResponse nodesInfoResponse =
    //
    // OpenSearchIntegTestCase.client().admin().cluster().nodesInfo(nodesInfoRequest).actionGet();
    //    List<PluginInfo> pluginInfos =
    //        nodesInfoResponse.getNodes().stream()
    //            .flatMap(
    //                (Function<NodeInfo, Stream<PluginInfo>>)
    //                    nodeInfo ->
    // nodeInfo.getInfo(PluginsAndModules.class).getPluginInfos().stream())
    //            .collect(Collectors.toList());
    //    pluginInfos.get(0);
    //    Assert.assertTrue(
    //        pluginInfos.stream()
    //            .anyMatch(pluginInfo -> pluginInfo.getName().equals("wazuh-indexer-setup")));
    // }

}
