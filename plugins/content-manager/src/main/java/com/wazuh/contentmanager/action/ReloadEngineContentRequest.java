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

import org.opensearch.action.support.nodes.BaseNodesRequest;
import org.opensearch.core.common.io.stream.StreamInput;

import java.io.IOException;

/**
 * Request for {@link ReloadEngineContentAction}. Carries no payload: it targets all nodes (a {@code
 * null} node filter resolves to every node in the cluster) and each node reads the current content
 * hash itself from the cluster-wide policies index.
 */
public class ReloadEngineContentRequest extends BaseNodesRequest<ReloadEngineContentRequest> {

    /** Creates a request targeting all nodes in the cluster. */
    public ReloadEngineContentRequest() {
        super((String[]) null);
    }

    public ReloadEngineContentRequest(StreamInput in) throws IOException {
        super(in);
    }
}
