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
package com.wazuh.contentmanager.utils;

import java.security.AccessController;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.model.command.Command;
import com.wazuh.contentmanager.model.cti.Changes;
import com.wazuh.contentmanager.model.cti.ConsumerInfo;

/** Privileged utility class for executing privileged HTTP requests. */
public class Privileged {

    /**
     * Executes an HTTP request with elevated privileges.
     *
     * @param request The Action to be executed with privileged permissions
     * @param <T> A privileged action that performs the HTTP request.
     * @return The return value resulting from the request execution.
     */
    public <T> T doPrivilegedRequest(java.security.PrivilegedAction<T> request) {
        return AccessController.doPrivileged(request);
    }

    /** Posts a command to the command manager API on a successful snapshot operation. */
    public void postUpdateCommand(CommandManagerClient client, ConsumerInfo current) {
        this.doPrivilegedRequest(
                () -> {
                    client.post(Command.create(String.valueOf(current.getOffset())));
                    return null;
                });
    }

    /**
     * Fetches the context changes between a given offset range from the CTI API.
     *
     * @param fromOffset Starting offset (inclusive).
     * @param toOffset Ending offset (exclusive).
     * @return ContextChanges object containing the changes.
     */
    public Changes getChanges(CTIClient client, long fromOffset, long toOffset) {
        return this.doPrivilegedRequest(() -> client.getChanges(fromOffset, toOffset, false));
    }
}
