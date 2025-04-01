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
package com.wazuh.setup.model.rbac;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.core.xcontent.XContentParserUtils;

import java.io.IOException;
import java.util.List;

import com.wazuh.setup.utils.ParseUtils;

/** Model class for a RBAC Policy Object */
public class Policy implements ToXContentObject {

    private static final String NAME = "name";
    private static final String ACTIONS = "actions";
    private static final String RESOURCES = "resources";
    private static final String EFFECT = "effect";
    private static final String LEVEL = "level";

    private final String name;
    private final List<Action> actions;
    private final List<Resource> resources;
    private final String effect;
    private final Long level;

    /**
     * Constructor for a Policy object
     *
     * @param name The name of the policy
     * @param actions The actions associated with the policy
     * @param resources The resources associated with the policy
     * @param effect Whether the actions are allowed on the resources or not
     * @param level Level of the policy
     */
    public Policy(
            String name, List<Action> actions, List<Resource> resources, String effect, Long level) {
        this.name = name;
        this.actions = actions;
        this.resources = resources;
        this.effect = effect;
        this.level = level;
    }

    /**
     * Parse function for a Policy object
     *
     * @param parser The parser object to append to
     * @return a Policy object
     * @throws IOException rethrown from XContentParser methods
     */
    public static Policy parse(XContentParser parser) throws IOException {
        String name = null;
        List<Action> actions = null;
        List<Resource> resources = null;
        String effect = null;
        Long level = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken() == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case NAME:
                        name = parser.text();
                        break;
                    case ACTIONS:
                        XContentParserUtils.ensureExpectedToken(
                                XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                        actions = ParseUtils.parseArray(parser, Action::parse);
                        break;
                    case RESOURCES:
                        XContentParserUtils.ensureExpectedToken(
                                XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                        resources = ParseUtils.parseArray(parser, Resource::parse);
                        break;
                    case EFFECT:
                        effect = parser.text();
                        break;
                    case LEVEL:
                        level = parser.longValue();
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }
        return new Policy(name, actions, resources, effect, level);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(NAME, this.name);
        builder.array(ACTIONS, this.actions);
        builder.array(RESOURCES, this.resources);
        builder.field(EFFECT, this.effect);
        builder.field(LEVEL, this.level);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Policy{"
                + "name='"
                + name
                + '\''
                + ", actions="
                + actions
                + ", resources="
                + resources
                + ", effect='"
                + effect
                + '\''
                + ", level="
                + level
                + '}';
    }
}
