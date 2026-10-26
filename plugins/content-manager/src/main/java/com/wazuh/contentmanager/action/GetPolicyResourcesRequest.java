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

/** Request carrying the space whose resources are listed. */
public class GetPolicyResourcesRequest extends ActionRequest {
    private final String space;

    /**
     * Constructor.
     *
     * @param space The space to list, as received from the query parameter.
     */
    public GetPolicyResourcesRequest(String space) {
        super();
        this.space = space;
    }

    /**
     * Stream constructor.
     *
     * @param sin The stream input.
     * @throws IOException If reading fails.
     */
    public GetPolicyResourcesRequest(StreamInput sin) throws IOException {
        super(sin);
        this.space = sin.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeOptionalString(space);
    }

    /**
     * Returns the requested space.
     *
     * @return The space, or {@code null} when absent.
     */
    public String getSpace() {
        return space;
    }
}
