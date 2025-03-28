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
package com.wazuh.contentmanager.model.commandmanager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;

/** This class represents the model of the posted command to the Command Manager API. */
public class Command {
    /** Constructs the JSON request body for the command. */
    private static final Logger log = LogManager.getLogger(Command.class);

    /**
     * Generates a CTI Command for the Command Manager API
     *
     * @return a command's XContentBuilder
     */
    public static String generateCtiCommand() {
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            return builder
                    .startObject()
                    .startArray("commands")
                    .startObject()
                    .startObject("action")
                    .startObject("args")
                    .field("index", "content-index")
                    .endObject()
                    .field("name", "update")
                    .field("version", "5.0.0") // Dynamic version
                    .endObject()
                    .field("source", "Content Manager")
                    .field("user", "Content Manager")
                    .field("timeout", 100)
                    .startObject("target")
                    .field("id", "TO-BE-DEFINED")
                    .field("type", "server")
                    .endObject()
                    .endObject()
                    .endArray()
                    .endObject()
                    .toString();
        } catch (IOException e) {
            log.error("Error building update command", e);
        }
        return null;
    }
}
