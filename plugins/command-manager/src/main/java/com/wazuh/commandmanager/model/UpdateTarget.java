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
package com.wazuh.commandmanager.model;

import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

/**
 * Represents a target for the "update" command. This class extends the Target class and is
 * specifically designed to handle updates to server targets with predefined constraints on type and
 * id.
 */
public class UpdateTarget extends Target {

    private static final String UPDATE_TYPE = "server";
    private static final String UPDATE_ID = "vulnerability-detector";

    /**
     * Default constructor.
     *
     * @param type The destination type. One of [`group`, `agent`, `server`]
     * @param id Unique identifier of the destination to send the command to.
     */
    public UpdateTarget(Type type, String id) {
        super(type, id);
    }

    /**
     * Parses the fields under "target" for the "update" command. Uses the {@link
     * Target#parse(XContentParser)} method and checks the values after that.
     *
     * @param parser xcontent parser.
     * @return Target instance.
     * @throws IOException unexpected exception parsing the content.
     * @throws IllegalArgumentException missing or invalid arguments.
     */
    public static Target parse(XContentParser parser) throws IOException, IllegalArgumentException {
        Target target = Target.parse(parser);

        if (target.getType() != Target.Type.SERVER) {
            throw new IllegalArgumentException(
                    "Expected [command.target.type] to contain ["
                            + UPDATE_TYPE
                            + "] value, got ["
                            + target.getType()
                            + "]");
        }
        if (!target.getId().equalsIgnoreCase(UPDATE_ID)) {
            throw new IllegalArgumentException(
                    "Expected [command.target.id] to contain ["
                            + UPDATE_ID
                            + "] value, got ["
                            + target.getId()
                            + "]");
        }

        return target;
    }
}
