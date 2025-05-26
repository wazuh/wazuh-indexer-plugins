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

import com.wazuh.commandmanager.spi.CommandRequest;
import com.wazuh.commandmanager.spi.CommandTransportAction;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;
import org.opensearch.core.action.ActionListener;

// import com.wazuh.common.transport.CommandRequest;
// import com.wazuh.common.transport.CommandRequestAction;
// import com.wazuh.common.transport.CommandResponse;

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
        if (CommandManagerClient.INSTANCE == null) {
            CommandManagerClient.INSTANCE = new CommandManagerClient(client);
        }
        return CommandManagerClient.INSTANCE;
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
    public void post(String requestBody) {

    //        CommandRequest request = new CommandRequest(json);
    //
    //        transportService.sendRequest(
    //            // target node — you may loop over all nodes or select by criteria
    //            transportService.getLocalNode(),
    //            Command.NAME,
    //            request,
    //            new ActionListenerResponseHandler<>(
    //                ActionListener.wrap(
    //                    response -> {
    //                        // handle success
    //                    },
    //                    exception -> {
    //                        // handle failure
    //                    }
    //                ),
    //                CommandResponse::new
    //            )
    //        );
            log.info("Posting command: {}", requestBody);
            CommandRequest request = new CommandRequest(requestBody);
            client.execute(
                    CommandTransportAction.ACTION_TYPE,
                    request,
                ActionListener.wrap(
                    response -> log.info("Command acknowledged: {}", response.isAcknowledged()),
                    e -> log.error("Failure", e)
                ));
        }
}
