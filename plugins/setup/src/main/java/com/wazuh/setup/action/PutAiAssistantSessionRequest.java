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
package com.wazuh.setup.action;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * Request carrying a single AI-assistant-session write. The {@link Operation} selects which of the
 * four writes the transport action performs; which REST route was hit determines it.
 *
 * <p>Only structural validation lives here — a missing path id, an empty body. Semantic validation
 * (title length, message count, the per-owner cap) belongs in the transport action, which reports
 * it as a {@code 400}/{@code 409} response body rather than as a failure.
 */
public class PutAiAssistantSessionRequest extends ActionRequest {

    /** The write this request performs. */
    public enum Operation {
        /** Append a new session owned by the caller. */
        CREATE,
        /** Replace an existing session's transcript, and its title when one is sent. */
        UPDATE,
        /** Change an existing session's title, and nothing else. */
        RENAME,
        /** Delete an existing session. */
        DELETE
    }

    private final Operation operation;
    private final String sessionId;
    private final String payload;

    /**
     * Constructs a new request.
     *
     * @param operation which write to perform.
     * @param sessionId session document id; required for every operation but {@code CREATE}, where
     *     the id is minted by OpenSearch.
     * @param payload raw JSON request body; required for every operation but {@code DELETE}.
     */
    public PutAiAssistantSessionRequest(Operation operation, String sessionId, String payload) {
        super();
        this.operation = operation;
        this.sessionId = sessionId;
        this.payload = payload;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public PutAiAssistantSessionRequest(StreamInput sin) throws IOException {
        super(sin);
        this.operation = sin.readEnum(Operation.class);
        this.sessionId = sin.readOptionalString();
        this.payload = sin.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (this.operation != Operation.CREATE
                && (this.sessionId == null || this.sessionId.isBlank())) {
            validationException = new ActionRequestValidationException();
            validationException.addValidationError("session id must not be empty");
        }
        if (this.operation != Operation.DELETE && (this.payload == null || this.payload.isBlank())) {
            if (validationException == null) {
                validationException = new ActionRequestValidationException();
            }
            validationException.addValidationError("request body must not be empty");
        }
        return validationException;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeEnum(this.operation);
        out.writeOptionalString(this.sessionId);
        out.writeOptionalString(this.payload);
    }

    public Operation getOperation() {
        return this.operation;
    }

    public String getSessionId() {
        return this.sessionId;
    }

    public String getPayload() {
        return this.payload;
    }
}
