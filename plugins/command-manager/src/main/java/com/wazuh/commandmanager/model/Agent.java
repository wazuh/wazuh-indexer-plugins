/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
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
