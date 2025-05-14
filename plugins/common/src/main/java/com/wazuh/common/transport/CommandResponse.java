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
package com.wazuh.commandmanager.transport;

import org.opensearch.core.action.ActionResponse;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.common.io.stream.StreamOutput;

import java.io.IOException;

/**
 * CommandResponseAction is a class that represents the response from the Command Manager Plugin
 * after posting a command. It extends the ActionResponse class and provides methods for
 * serialization.
 */
public class CommandResponse extends ActionResponse {
    private final String message;

    /**
     * Constructor for CommandResponseAction.
     *
     * @param message the message from the command response
     */
    public CommandResponseAction(String message) {
        this.message = message;
    }

    /**
     * Constructor for CommandResponseAction that reads from a StreamInput.
     *
     * @param in the StreamInput to read from
     * @throws IOException if an I/O error occurs
     */
    public CommandResponseAction(StreamInput in) throws IOException {
        super(in);
        this.message = in.readString();
    }

    /**
     * Returns the message from the command response.
     *
     * @return the message from the command response
     */
    public String getMessage() {
        return message;
    }

    /*
     * Writes the message to the StreamOutput.
     *
     * @param out the StreamOutput to write to
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void writeTo(StreamOutput out) throws IOException {
        out.writeString(message);
    }
}
