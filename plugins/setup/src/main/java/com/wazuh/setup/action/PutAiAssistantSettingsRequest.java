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
 * Request carrying a single AI-assistant-settings write. The {@link Operation} selects which of the
 * three writes the transport action performs; which REST route was hit determines it.
 */
public class PutAiAssistantSettingsRequest extends ActionRequest {

    /** The write this request performs. */
    public enum Operation {
        /** Upsert the {@code settings}/{@code field_policy} document. */
        SETTINGS,
        /** Create or update a provider document. */
        PUT_PROVIDER,
        /** Delete a provider document. */
        DELETE_PROVIDER
    }

    private final Operation operation;
    private final String providerId;
    private final String payload;

    /**
     * Constructs a new request.
     *
     * @param operation which write to perform.
     * @param providerId provider document id; required for {@code PUT_PROVIDER} (may be blank to
     *     request a generated id) and {@code DELETE_PROVIDER}, unused for {@code SETTINGS}.
     * @param payload raw JSON request body; required for {@code SETTINGS} and {@code PUT_PROVIDER},
     *     unused for {@code DELETE_PROVIDER}.
     */
    public PutAiAssistantSettingsRequest(Operation operation, String providerId, String payload) {
        super();
        this.operation = operation;
        this.providerId = providerId;
        this.payload = payload;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public PutAiAssistantSettingsRequest(StreamInput sin) throws IOException {
        super(sin);
        this.operation = sin.readEnum(Operation.class);
        this.providerId = sin.readOptionalString();
        this.payload = sin.readOptionalString();
    }

    @Override
    public ActionRequestValidationException validate() {
        ActionRequestValidationException validationException = null;
        if (this.operation == Operation.DELETE_PROVIDER
                && (this.providerId == null || this.providerId.isBlank())) {
            validationException = new ActionRequestValidationException();
            validationException.addValidationError("provider id must not be empty");
        }
        if ((this.operation == Operation.SETTINGS || this.operation == Operation.PUT_PROVIDER)
                && (this.payload == null || this.payload.isBlank())) {
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
        out.writeOptionalString(this.providerId);
        out.writeOptionalString(this.payload);
    }

    public Operation getOperation() {
        return this.operation;
    }

    public String getProviderId() {
        return this.providerId;
    }

    public String getPayload() {
        return this.payload;
    }
}
