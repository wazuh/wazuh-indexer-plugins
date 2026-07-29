/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.nodes.BaseNodeResponse;
import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.action.support.nodes.BaseNodesResponse;
import org.opensearch.action.support.nodes.TransportNodesAction;
import org.opensearch.cluster.ClusterName;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.env.Environment;
import org.opensearch.secure_sm.AccessController;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportRequest;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import com.wazuh.contentmanager.action.PromoteSnapshotAction;
import com.wazuh.contentmanager.cti.catalog.service.SnapshotServiceImpl;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Broadcasts a snapshot-promote request to every node in the cluster. Each node moves its local
 * packaged snapshot (e.g. {@code ruleset.zip}) to the stable path ({@code ruleset.stable.zip}) so
 * it is available for rollback if the node later becomes cluster manager.
 */
public class TransportPromoteSnapshotAction
        extends TransportNodesAction<
                TransportPromoteSnapshotAction.NodesRequest,
                TransportPromoteSnapshotAction.NodesResponse,
                TransportPromoteSnapshotAction.NodeRequest,
                TransportPromoteSnapshotAction.NodeResponse> {

    private static final Logger log = LogManager.getLogger(TransportPromoteSnapshotAction.class);

    private final Environment environment;

    @Inject
    public TransportPromoteSnapshotAction(
            ThreadPool threadPool,
            ClusterService clusterService,
            TransportService transportService,
            ActionFilters actionFilters,
            Environment environment) {
        super(
                PromoteSnapshotAction.NAME,
                threadPool,
                clusterService,
                transportService,
                actionFilters,
                NodesRequest::new,
                NodeRequest::new,
                ThreadPool.Names.GENERIC,
                NodeResponse.class);
        this.environment = environment;
    }

    @Override
    protected NodeRequest newNodeRequest(NodesRequest request) {
        return new NodeRequest(request.getSnapshotFilename());
    }

    @Override
    protected NodeResponse newNodeResponse(StreamInput in) throws IOException {
        return new NodeResponse(in);
    }

    @Override
    protected NodesResponse newResponse(
            NodesRequest request, List<NodeResponse> responses, List<FailedNodeException> failures) {
        return new NodesResponse(clusterService.getClusterName(), responses, failures);
    }

    @Override
    protected NodeResponse nodeOperation(NodeRequest request) {
        DiscoveryNode localNode = clusterService.localNode();
        Path pluginsDir = environment.pluginsDir();
        if (pluginsDir == null) {
            return new NodeResponse(localNode, true);
        }

        Path snapshotsDir =
                pluginsDir.resolve(Constants.PLUGIN_DIR_NAME).resolve(Constants.CTI_SNAPSHOTS_DIR);
        Path source = snapshotsDir.resolve(request.getSnapshotFilename());
        String stableFilename =
                request.getSnapshotFilename().replace(".zip", Constants.STABLE_SNAPSHOT_SUFFIX);
        Path stablePath = snapshotsDir.resolve(stableFilename);

        try {
            boolean sourceExists = AccessController.doPrivilegedChecked(() -> Files.exists(source));
            if (!sourceExists) {
                log.debug(Constants.D_LOG_SNAPSHOT_PROMOTE_SOURCE_MISSING, source);
                return new NodeResponse(localNode, true);
            }
        } catch (Exception e) {
            log.warn(Constants.W_LOG_SNAPSHOT_PROMOTE_CHECK_FAILED, source, e.getMessage());
            return new NodeResponse(localNode, false);
        }

        boolean result = SnapshotServiceImpl.promoteToStable(source, stablePath);
        return new NodeResponse(localNode, result);
    }

    /** Cluster-wide request carrying the snapshot filename to promote. */
    public static class NodesRequest extends BaseNodesRequest<NodesRequest> {
        private final String snapshotFilename;

        public NodesRequest(String snapshotFilename) {
            super(new String[0]);
            this.snapshotFilename = snapshotFilename;
        }

        public NodesRequest(StreamInput in) throws IOException {
            super(in);
            this.snapshotFilename = in.readString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(snapshotFilename);
        }

        public String getSnapshotFilename() {
            return snapshotFilename;
        }
    }

    /** Per-node request carrying the snapshot filename. */
    public static class NodeRequest extends TransportRequest {
        private final String snapshotFilename;

        public NodeRequest(String snapshotFilename) {
            this.snapshotFilename = snapshotFilename;
        }

        public NodeRequest(StreamInput in) throws IOException {
            super(in);
            this.snapshotFilename = in.readString();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeString(snapshotFilename);
        }

        public String getSnapshotFilename() {
            return snapshotFilename;
        }
    }

    /** Per-node response indicating whether the promote succeeded. */
    public static class NodeResponse extends BaseNodeResponse {
        private final boolean success;

        public NodeResponse(DiscoveryNode node, boolean success) {
            super(node);
            this.success = success;
        }

        public NodeResponse(StreamInput in) throws IOException {
            super(in);
            this.success = in.readBoolean();
        }

        @Override
        public void writeTo(StreamOutput out) throws IOException {
            super.writeTo(out);
            out.writeBoolean(success);
        }

        public boolean isSuccess() {
            return success;
        }
    }

    /** Aggregated response from all nodes. */
    public static class NodesResponse extends BaseNodesResponse<NodeResponse> {
        public NodesResponse(StreamInput in) throws IOException {
            super(in);
        }

        public NodesResponse(
                ClusterName clusterName, List<NodeResponse> nodes, List<FailedNodeException> failures) {
            super(clusterName, nodes, failures);
        }

        @Override
        protected List<NodeResponse> readNodesFrom(StreamInput in) throws IOException {
            return in.readList(NodeResponse::new);
        }

        @Override
        protected void writeNodesTo(StreamOutput out, List<NodeResponse> nodes) throws IOException {
            out.writeList(nodes);
        }
    }
}
