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
package com.wazuh.contentmanager.action;

import org.opensearch.action.FailedNodeException;
import org.opensearch.action.support.nodes.BaseNodesResponse;
import org.opensearch.cluster.ClusterName;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;
import java.util.List;

/** Aggregate response for {@link ReloadEngineContentAction}: one entry per responding node. */
public class ReloadEngineContentResponse
        extends BaseNodesResponse<ReloadEngineContentNodeResponse> {

    public ReloadEngineContentResponse(StreamInput in) throws IOException {
        super(in);
    }

    public ReloadEngineContentResponse(
            ClusterName clusterName,
            List<ReloadEngineContentNodeResponse> nodes,
            List<FailedNodeException> failures) {
        super(clusterName, nodes, failures);
    }

    @Override
    protected List<ReloadEngineContentNodeResponse> readNodesFrom(StreamInput in) throws IOException {
        return in.readList(ReloadEngineContentNodeResponse::new);
    }

    @Override
    protected void writeNodesTo(StreamOutput out, List<ReloadEngineContentNodeResponse> nodes)
            throws IOException {
        out.writeList(nodes);
    }
}
