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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.client.Client;
import org.opensearch.common.inject.Inject;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.io.IOException;
import java.util.List;

import com.wazuh.commandmanager.index.CommandIndex;
import com.wazuh.commandmanager.model.Command;
import com.wazuh.commandmanager.model.Orders;
import com.wazuh.commandmanager.spi.CommandRequest;
import com.wazuh.commandmanager.spi.CommandResponse;
import com.wazuh.commandmanager.spi.CommandRequestAction;

/**
 * CommandTransportAction is a class that handles the transport action for posting commands to the
 * Command Manager Plugin. It extends the HandledTransportAction class and provides methods for
 * executing the action.
 */
public class CommandTransportAction
        extends HandledTransportAction<CommandRequest, CommandResponse> {
    private static final Logger log = LogManager.getLogger(CommandTransportAction.class);
    private final Client client;
    private final CommandIndex commandIndex;

    /**
     * Constructor for CommandTransportAction.
     *
     * @param transportService the TransportService to use
     * @param actionFilters the ActionFilters to use
     * @param client
     * @param commandIndex
     */
    @Inject
    public CommandTransportAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            CommandIndex commandIndex) {
        super(CommandRequestAction.NAME, transportService, actionFilters, CommandRequest::new);
        this.client = client;
        this.commandIndex = commandIndex;
    }

    /**
     * Executes the transport action for posting commands to the Command Manager Plugin.
     *
     * @param task the task associated with the action
     * @param request the CommandRequest to execute
     * @param listener the ActionListener to notify when the action is complete
     */
    @Override
    protected void doExecute(
            Task task, CommandRequest request, ActionListener<CommandResponse> listener) {
        String jsonBody = request.getJsonBody();
        log.info("Transport Action request received: {}", jsonBody);
        try {
            List<Command> commands =
                    Command.parseArray(
                            XContentType.JSON
                                    .xContent()
                                    .createParser(
                                            NamedXContentRegistry.EMPTY,
                                            DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                                            jsonBody));
            if (commands.isEmpty()) {
                listener.onFailure(new IllegalArgumentException("No commands provided"));
                return;
            }
            Orders orders = Orders.fromCommands(this.client, commands);
            commandIndex
                    .asyncBulkCreate(orders.get())
                    .thenAccept(
                            status -> {
                                listener.onResponse(new CommandResponse("Command received: " + jsonBody));
                            })
                    .exceptionally(
                            e -> {
                                listener.onFailure(
                                        e instanceof Exception ? (Exception) e : new RuntimeException(e));
                                return null;
                            });

        } catch (IOException e) {
            listener.onFailure(e);
        }
    }
}
