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

import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Response for GET /subscription.
 *
 * <p>On success, builds a nested JSON with plan details and registration state, plus the CTI
 * Console environment of a registered instance. On error, falls back to a simple message + status
 * response.
 */
public class GetSubscriptionResponse extends ActionResponse implements ToXContent {
    private final String message;
    private final RestStatus status;
    private final String planName;
    private final boolean planIsPublic;
    private final boolean isRegistered;
    private final String environment;
    private final boolean isError;

    /**
     * Construct a successful response with plan details and no environment.
     *
     * @param planName the plan name, or null if unavailable
     * @param planIsPublic whether the plan is public
     * @param isRegistered whether the subscription is registered
     */
    public GetSubscriptionResponse(String planName, boolean planIsPublic, boolean isRegistered) {
        this(planName, planIsPublic, isRegistered, null);
    }

    /**
     * Construct a successful response with plan details and the CTI Console environment.
     *
     * @param planName the plan name, or null if unavailable
     * @param planIsPublic whether the plan is public
     * @param isRegistered whether the subscription is registered
     * @param environment the JSON object the CTI Console answered to {@code GET
     *     /platform/environments/me}, written as is under {@code message.environment}, or {@code
     *     null} to leave the field out. It must be a single, well-formed JSON object, as a parsed
     *     answer serializes to.
     */
    public GetSubscriptionResponse(
            String planName, boolean planIsPublic, boolean isRegistered, String environment) {
        super();
        this.message = null;
        this.status = RestStatus.OK;
        this.planName = planName;
        this.planIsPublic = planIsPublic;
        this.isRegistered = isRegistered;
        this.environment = environment;
        this.isError = false;
    }

    /**
     * Construct an error response with a simple message.
     *
     * @param message error message
     * @param status HTTP status
     */
    public GetSubscriptionResponse(String message, RestStatus status) {
        super();
        this.message = message;
        this.status = status;
        this.planName = null;
        this.planIsPublic = false;
        this.isRegistered = false;
        this.environment = null;
        this.isError = true;
    }

    public GetSubscriptionResponse(StreamInput sin) throws IOException {
        this.isError = sin.readBoolean();
        this.status = sin.readEnum(RestStatus.class);
        if (this.isError) {
            this.message = sin.readString();
            this.planName = null;
            this.planIsPublic = false;
            this.isRegistered = false;
            this.environment = null;
        } else {
            this.message = null;
            this.planName = sin.readOptionalString();
            this.planIsPublic = sin.readBoolean();
            this.isRegistered = sin.readBoolean();
            this.environment = sin.readOptionalString();
        }
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeBoolean(this.isError);
        out.writeEnum(this.status);
        if (this.isError) {
            out.writeString(this.message);
        } else {
            out.writeOptionalString(this.planName);
            out.writeBoolean(this.planIsPublic);
            out.writeBoolean(this.isRegistered);
            out.writeOptionalString(this.environment);
        }
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        if (this.isError) {
            builder.field(Constants.KEY_MESSAGE, this.message);
        } else {
            builder
                    .startObject(Constants.KEY_MESSAGE)
                    .startObject("plan")
                    .field("name", this.planName)
                    .field("is_public", this.planIsPublic)
                    .endObject()
                    .field("is_registered", this.isRegistered);
            if (this.environment != null) {
                // Written as raw JSON, not parsed again, unless the builder pretty-prints or filters.
                builder.rawField(
                        Constants.KEY_ENVIRONMENT,
                        new ByteArrayInputStream(this.environment.getBytes(StandardCharsets.UTF_8)),
                        XContentType.JSON);
            }
            builder.endObject();
        }
        builder.field(Constants.KEY_STATUS, this.status.getStatus());
        return builder.endObject();
    }

    public RestStatus getStatus() {
        return this.status;
    }
}
