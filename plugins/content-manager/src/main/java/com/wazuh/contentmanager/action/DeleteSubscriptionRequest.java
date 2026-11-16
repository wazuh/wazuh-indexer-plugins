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
 * Request for {@link DeleteSubscriptionAction}.
 *
 * <p>Two shapes, distinguished by {@link #isPermissionCheckOnly()}:
 *
 * <ul>
 *   <li>a real deletion of the stored CTI credentials;
 *   <li>a permission check, built with {@link #permissionCheck()}. It exists only so the request
 *       reaches the security plugin's action filter, which answers it instead of letting the action
 *       execute.
 * </ul>
 */
public class DeleteSubscriptionRequest extends ActionRequest {

    private final boolean permissionCheckOnly;

    /** Builds a deletion request. */
    public DeleteSubscriptionRequest() {
        this(false);
    }

    private DeleteSubscriptionRequest(boolean permissionCheckOnly) {
        super();
        this.permissionCheckOnly = permissionCheckOnly;
    }

    /**
     * Builds a request that only exercises the authorization filter. It must never remove the stored
     * credentials.
     *
     * @return a permission-check-only request
     */
    public static DeleteSubscriptionRequest permissionCheck() {
        return new DeleteSubscriptionRequest(true);
    }

    /**
     * Deserializing constructor.
     *
     * @param sin the stream to read from
     * @throws IOException on read failure
     */
    public DeleteSubscriptionRequest(StreamInput sin) throws IOException {
        super(sin);
        this.permissionCheckOnly = sin.readBoolean();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeBoolean(this.permissionCheckOnly);
    }

    /**
     * @return true when this request must not remove the stored credentials
     */
    public boolean isPermissionCheckOnly() {
        return this.permissionCheckOnly;
    }
}
