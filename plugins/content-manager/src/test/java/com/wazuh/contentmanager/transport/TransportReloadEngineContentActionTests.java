/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.transport;

import org.opensearch.Version;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.junit.Before;

import java.util.Collections;
import java.util.List;

import com.wazuh.contentmanager.action.ReloadEngineContentNodeResponse;
import com.wazuh.contentmanager.action.ReloadEngineContentRequest;
import com.wazuh.contentmanager.action.ReloadEngineContentResponse;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class TransportReloadEngineContentActionTests extends OpenSearchTestCase {

    private EngineContentLoader loader;
    private ClusterService clusterService;
    private DiscoveryNode localNode;
    private TransportReloadEngineContentAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.loader = mock(EngineContentLoader.class);
        this.localNode = new DiscoveryNode("node-1", buildNewFakeTransportAddress(), Version.CURRENT);
        this.clusterService = mock(ClusterService.class);
        when(this.clusterService.getClusterName()).thenReturn(new ClusterName("test-cluster"));
        when(this.clusterService.localNode()).thenReturn(this.localNode);
        this.action =
                new TransportReloadEngineContentAction(
                        mock(ThreadPool.class),
                        this.clusterService,
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        this.loader);
    }

    /** The node handler delegates to the hash-gated loader and reports the local node. */
    public void testNodeOperationTriggersReload() {
        ReloadEngineContentNodeResponse response =
                this.action.nodeOperation(new TransportReloadEngineContentAction.NodeRequest());

        verify(this.loader, times(1)).reloadIfChanged();
        assertEquals(this.localNode, response.getNode());
    }

    /** newResponse aggregates node responses under the cluster name. */
    public void testNewResponseAggregatesNodes() {
        ReloadEngineContentNodeResponse nodeResponse =
                new ReloadEngineContentNodeResponse(this.localNode);

        ReloadEngineContentResponse response =
                this.action.newResponse(
                        new ReloadEngineContentRequest(), List.of(nodeResponse), Collections.emptyList());

        assertEquals("test-cluster", response.getClusterName().value());
        assertEquals(1, response.getNodes().size());
        assertEquals(this.localNode, response.getNodes().get(0).getNode());
    }

    /** The per-node response round-trips over the wire. */
    public void testNodeResponseSerialization() throws Exception {
        ReloadEngineContentNodeResponse original = new ReloadEngineContentNodeResponse(this.localNode);

        BytesStreamOutput out = new BytesStreamOutput();
        original.writeTo(out);
        ReloadEngineContentNodeResponse read =
                new ReloadEngineContentNodeResponse(out.bytes().streamInput());

        assertEquals(this.localNode, read.getNode());
    }
}
