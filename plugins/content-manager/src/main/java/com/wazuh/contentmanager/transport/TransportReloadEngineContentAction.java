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

import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.action.ReloadEngineContentAction;
import com.wazuh.contentmanager.action.ReloadEngineContentNodeResponse;
import com.wazuh.contentmanager.action.ReloadEngineContentRequest;
import com.wazuh.contentmanager.action.ReloadEngineContentResponse;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;

/**
 * Handles {@link ReloadEngineContentAction} on every targeted node: it asks the node-local {@link
 * EngineContentLoader} to reload the STANDARD space if the cluster-wide content hash changed.
 *
 * <p>The call is hash-gated and single-flighted inside the loader, so this handler is a cheap no-op
 * when the node's Engine is already up to date, and the broadcast composes safely with the per-node
 * cluster-state listener that drives the same loader.
 */
public class TransportReloadEngineContentAction
        extends TransportNodesAction<
                ReloadEngineContentRequest,
                ReloadEngineContentResponse,
                TransportReloadEngineContentAction.NodeRequest,
                ReloadEngineContentNodeResponse> {

    private final EngineContentLoader engineContentLoader;

    @Inject
    public TransportReloadEngineContentAction(
            ThreadPool threadPool,
            ClusterService clusterService,
            TransportService transportService,
            ActionFilters actionFilters,
            EngineContentLoader engineContentLoader) {
        super(
                ReloadEngineContentAction.NAME,
                threadPool,
                clusterService,
                transportService,
                actionFilters,
                ReloadEngineContentRequest::new,
                NodeRequest::new,
                ThreadPool.Names.GENERIC,
                ReloadEngineContentNodeResponse.class);
        this.engineContentLoader = engineContentLoader;
    }

    @Override
    protected ReloadEngineContentResponse newResponse(
            ReloadEngineContentRequest request,
            List<ReloadEngineContentNodeResponse> responses,
            List<FailedNodeException> failures) {
        return new ReloadEngineContentResponse(clusterService.getClusterName(), responses, failures);
    }

    @Override
    protected NodeRequest newNodeRequest(ReloadEngineContentRequest request) {
        return new NodeRequest();
    }

    @Override
    protected ReloadEngineContentNodeResponse newNodeResponse(StreamInput in) throws IOException {
        return new ReloadEngineContentNodeResponse(in);
    }

    @Override
    protected ReloadEngineContentNodeResponse nodeOperation(NodeRequest request) {
        this.engineContentLoader.reloadIfChanged();
        return new ReloadEngineContentNodeResponse(clusterService.localNode());
    }

    /** Per-node request. Empty: the node reads the content hash itself from the policies index. */
    public static class NodeRequest extends TransportRequest {
        public NodeRequest() {}

        public NodeRequest(StreamInput in) throws IOException {
            super(in);
        }
    }
}
