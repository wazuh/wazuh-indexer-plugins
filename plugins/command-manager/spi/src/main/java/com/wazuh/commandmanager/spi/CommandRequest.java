/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.commandmanager.spi;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * CommandRequest is a class that represents a request to post a command to the Command Manager
 * Plugin. It extends the ActionRequest class and provides methods for serialization and validation.
 */
public class CommandRequest extends ActionRequest {
    private final String jsonBody;

    /**
     * Constructor for CommandRequest.
     *
     * @param jsonBody the JSON body of the command request
     */
    public CommandRequest(String jsonBody) {
        this.jsonBody = jsonBody;
    }

    /**
     * Constructor for CommandRequest that reads from a StreamInput.
     *
     * @param in the StreamInput to read from
     * @throws IOException if an I/O error occurs
     */
    public CommandRequest(StreamInput in) throws IOException {
        super(in);
        this.jsonBody = in.readString();
    }

    @Override
    public ActionRequestValidationException validate() {
        return null;
    }

    /**
     * Returns the JSON body of the command request.
     *
     * @return the JSON body of the command request
     */
    public String getJsonBody() {
        return jsonBody;
    }

    /**
     * Writes the command request to a StreamOutput.
     *
     * @param out the StreamOutput to write to
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(jsonBody);
    }
}
