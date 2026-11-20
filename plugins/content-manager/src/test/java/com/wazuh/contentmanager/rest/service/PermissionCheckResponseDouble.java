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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.common.xcontent.StatusToXContentObject;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Set;

import com.wazuh.contentmanager.action.MessageStatusResponse;

/**
 * Stand-in for {@code org.opensearch.security.action.simulate.PermissionCheckResponse}, which lives
 * in the security plugin's classloader and cannot be referenced from here. It reproduces the two
 * properties that matter: it is an {@link ActionResponse} but not a {@link MessageStatusResponse},
 * and it is a {@link StatusToXContentObject}.
 */
class PermissionCheckResponseDouble extends ActionResponse implements StatusToXContentObject {
    private final boolean accessAllowed;
    private final Set<String> missingPrivileges;

    PermissionCheckResponseDouble(boolean accessAllowed, Set<String> missingPrivileges) {
        this.accessAllowed = accessAllowed;
        this.missingPrivileges = missingPrivileges;
    }

    @Override
    public RestStatus status() {
        return RestStatus.OK;
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder
                .startObject()
                .field("accessAllowed", this.accessAllowed)
                .field("missingPrivileges", this.missingPrivileges)
                .endObject();
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(this.accessAllowed);
        out.writeStringCollection(this.missingPrivileges);
    }
}
