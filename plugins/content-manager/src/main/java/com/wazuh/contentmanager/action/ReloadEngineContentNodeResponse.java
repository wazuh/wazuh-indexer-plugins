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

import org.opensearch.action.support.nodes.BaseNodeResponse;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.core.common.io.stream.StreamInput;

import java.io.IOException;

/**
 * Per-node response for {@link ReloadEngineContentAction}. Its presence in the aggregate response
 * confirms the node accepted (scheduled) the reload; the actual load result is reported through the
 * node's own Engine load logs. Carries no payload beyond the node identity.
 */
public class ReloadEngineContentNodeResponse extends BaseNodeResponse {

    public ReloadEngineContentNodeResponse(DiscoveryNode node) {
        super(node);
    }

    public ReloadEngineContentNodeResponse(StreamInput in) throws IOException {
        super(in);
    }
}
