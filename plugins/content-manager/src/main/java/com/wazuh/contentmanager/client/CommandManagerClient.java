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
package com.wazuh.contentmanager.client;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.core.action.ActionListener;

import com.wazuh.contentmanager.client.actions.CommandActionType;
import com.wazuh.contentmanager.client.actions.CommandRequestAction;
import com.wazuh.contentmanager.client.actions.CommandResponseAction;

/**
 * CommandManagerClient is a singleton class that provides a client for posting commands to the
 * Command Manager Plugin. It uses the OpenSearch client to execute actions and handle responses.
 */
public class CommandManagerClient {
    private static final Logger log = LogManager.getLogger(CommandManagerClient.class);
    private static CommandManagerClient INSTANCE;

    private final Client client;

    /**
     * Private constructor to prevent instantiation.
     *
     * @param client the OpenSearch client
     */
    private CommandManagerClient(Client client) {
        this.client = client;
    }

    /**
     * Returns the singleton instance of CommandManagerClient.
     *
     * @param client the OpenSearch client
     * @return the singleton instance of CommandManagerClient
     */
    public static synchronized CommandManagerClient getInstance(Client client) {
        if (INSTANCE == null) {
            INSTANCE = new CommandManagerClient(client);
        }
        return INSTANCE;
    }

    /**
     * Returns the singleton instance of CommandManagerClient.
     *
     * @return the singleton instance of CommandManagerClient
     * @throws IllegalStateException if the client has not been initialized
     */
    public static synchronized CommandManagerClient getInstance() {
        if (INSTANCE == null) {
            throw new IllegalStateException("Command Manager client have not been initialized.");
        }
        return INSTANCE;
    }

    /**
     * Posts a command to the Command Manager Plugin.
     *
     * @param requestBody the command request body
     */
    public void postCommand(String requestBody) {
        CommandRequestAction request = new CommandRequestAction(requestBody);
        client.execute(
                CommandActionType.INSTANCE,
                request,
                new ActionListener<>() {
                    @Override
                    public void onResponse(CommandResponseAction response) {
                        log.info("Command successfully posted: {}", response.getMessage());
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to post command", e);
                    }
                });
    }
}
