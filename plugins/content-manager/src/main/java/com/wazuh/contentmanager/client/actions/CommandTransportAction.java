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
package com.wazuh.contentmanager.client.actions;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

/**
 * CommandTransportAction is a class that handles the transport action for posting commands to the
 * Command Manager Plugin. It extends the HandledTransportAction class and provides methods for
 * executing the action.
 */
public class CommandTransportAction
        extends HandledTransportAction<CommandRequestAction, CommandResponseAction> {

    /**
     * Constructor for CommandTransportAction.
     *
     * @param transportService the TransportService to use
     * @param actionFilters the ActionFilters to use
     */
    @Inject
    public CommandTransportAction(TransportService transportService, ActionFilters actionFilters) {
        super(CommandActionType.NAME, transportService, actionFilters, CommandRequestAction::new);
    }

    /**
     * Executes the transport action for posting commands to the Command Manager Plugin.
     *
     * @param task the task associated with the action
     * @param request the CommandRequestAction to execute
     * @param listener the ActionListener to notify when the action is complete
     */
    @Override
    protected void doExecute(
            Task task, CommandRequestAction request, ActionListener<CommandResponseAction> listener) {
        String jsonBody = request.getJsonBody();
        listener.onResponse(new CommandResponseAction("Command received: " + jsonBody));
    }
}
