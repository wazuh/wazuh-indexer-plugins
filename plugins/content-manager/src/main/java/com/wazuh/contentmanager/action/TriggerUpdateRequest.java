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

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * Request of an on-demand content update ({@code POST /_plugins/_content_manager/update}).
 * Optionally offline: the pass then loads the snapshot files placed on the node instead of asking
 * Wazuh CTI.
 */
public class TriggerUpdateRequest extends ActionRequest {

    /** Whether the update is an offline one. */
    private final boolean offline;

    /** Creates the request of a regular, online update. */
    public TriggerUpdateRequest() {
        this(false);
    }

    /**
     * Creates the request of an update.
     *
     * @param offline Whether to load the snapshot files placed on the node instead of asking Wazuh
     *     CTI.
     */
    public TriggerUpdateRequest(boolean offline) {
        super();
        this.offline = offline;
    }

    /**
     * Reads the request from a stream.
     *
     * @param sin The stream.
     * @throws IOException if it cannot be read.
     */
    public TriggerUpdateRequest(StreamInput sin) throws IOException {
        super(sin);
        this.offline = sin.readBoolean();
    }

    /**
     * Returns whether the update is an offline one.
     *
     * @return {@code true} for an offline update.
     */
    public boolean isOffline() {
        return this.offline;
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeBoolean(this.offline);
    }
}
