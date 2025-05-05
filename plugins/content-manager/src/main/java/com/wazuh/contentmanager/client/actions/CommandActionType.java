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

import org.opensearch.action.ActionType;

/**
 * CommandActionType is a class that defines the action type for posting commands to the Command
 * Manager Plugin. It extends the ActionType class and provides a static instance for easy access.
 */
public class CommandActionType extends ActionType<CommandResponseAction> {
    /** The name/endpoint of the action. */
    public static final String NAME = "cluster:command_manager/post_command";

    /** The action type for the command response. */
    public static final CommandActionType INSTANCE = new CommandActionType();

    /** Constructor for CommandActionType. */
    private CommandActionType() {
        super(NAME, CommandResponseAction::new);
    }
}
