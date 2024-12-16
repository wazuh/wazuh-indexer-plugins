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
import java.util.List;

/** Command's agent fields. */
public class Agent implements ToXContentObject {
    public static final String AGENT = "agent";
    public static final String GROUPS = "groups";
    private final List<String> groups;

    /**
     * Default constructor.
     *
     * @param groups Agent's groups
     */
    public Agent(List<String> groups) {
        this.groups = groups;
    }

    /**
     * @param parser
     * @return
     * @throws IOException
     */
    public static Agent parse(XContentParser parser) throws IOException {
        List<Object> groups = List.of();

        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            String fieldName = parser.currentName();
            parser.nextToken();
            if (fieldName.equals(GROUPS)) {
                groups = parser.list();
            } else {
                parser.skipChildren();
            }
        }

        // Cast args field Object list to String list
        List<String> convertedGroupFields = (List<String>) (List<?>) (groups);
        return new Agent(convertedGroupFields);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(AGENT);
        builder.field(GROUPS, this.groups);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Agent{" + "groups=" + groups + '}';
    }
}
