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
import java.util.HashMap;

public class FetchConfigCommand extends Args {

    /**
     * Parses an args XContentParser into an Args object. A {@code Map<String,Object>} is created
     * with the fields and values from the command.action.args object
     *
     * @param parser An XContentParser containing an args to be deserialized
     * @return An Args object
     * @throws IOException Rethrows the exception from list() and objectText() methods
     */
    public static Args parse(XContentParser parser) throws IOException {
        parser.skipChildren();
        return new Args(new HashMap<>());
    }
}
