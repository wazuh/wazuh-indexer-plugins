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
 * Request to read either the settings/field_policy document, or the full provider list. The {@link
 * Operation} selects which; which REST route was hit determines it.
 */
public class GetAiAssistantSettingsRequest extends ActionRequest {

    /** The read this request performs. */
    public enum Operation {
        /** Read the {@code settings}/{@code field_policy} document. */
        SETTINGS,
        /** List every provider document. */
        LIST_PROVIDERS
    }

    private final Operation operation;

    /**
     * Constructs a new request.
     *
     * @param operation which read to perform.
     */
    public GetAiAssistantSettingsRequest(Operation operation) {
        super();
        this.operation = operation;
    }

    /**
     * Stream deserialization constructor.
     *
     * @param sin the stream input.
     * @throws IOException if reading from the stream fails.
     */
    public GetAiAssistantSettingsRequest(StreamInput sin) throws IOException {
        super(sin);
        this.operation = sin.readEnum(Operation.class);
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    @Override
    public void writeTo(StreamOutput out) throws IOException {
        super.writeTo(out);
        out.writeEnum(this.operation);
    }

    public Operation getOperation() {
        return this.operation;
    }
}
