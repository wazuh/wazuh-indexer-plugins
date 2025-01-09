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

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

/** Handles the command.action.args object */
public class Args implements ToXContentObject {

    public static final String ARGS = "args";
    private final Object args;

    /**
     * Constructor method
     *
     * @param args Initializes the args object
     */
    public Args(Object args) {
        this.args = args;
    }

    /**
     * Parses an args XContentParser. This is mostly meant to handle List<> objects as a separate
     * case
     *
     * @param parser An XContentParser containing an args to be deserialized
     * @return An Args object
     * @throws IOException Rethrows the exception from list() and objectText() methods
     */
    public static Args parse(XContentParser parser) throws IOException {
        Object args = null;

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            XContentParser.Token currentToken = parser.currentToken();
            parser.nextToken();
            if (currentToken == XContentParser.Token.START_ARRAY) {
                args = parser.list();
            } else {
                args = parser.objectText();
            }
        }
        return new Args(args);
    }

    /**
     * Builds an args XContentBuilder
     *
     * @param builder This is received from the parent object
     * @param params Not used
     * @return A complete args XContentBuilder object
     * @throws IOException rethrown from XContentBuilder objects within
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(Args.ARGS);
        builder.value(this.args);
        return builder.endObject();
    }

    /**
     * @return a String representation of the contents of the Args object
     */
    @Override
    public String toString() {
        return "Args{" + "args='" + args + '\'' + '}';
    }
}
