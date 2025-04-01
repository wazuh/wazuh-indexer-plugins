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

/** Model class for a RBAC Role Object */
public class Role implements ToXContentObject {

    private static final String NAME = "name";
    private static final String LEVEL = "level";
    private static final String POLICIES = "policies";
    private static final String RULES = "rules";

    private final String name;
    private final Long level;
    private final List<Policy> policies;
    private final List<Rule> rules;

    /**
     * Class constructor
     *
     * @param name The name of the role
     * @param level The level of the role
     * @param policies An array of policies associated with this role
     * @param rules An array of rules for the role
     */
    public Role(String name, Long level, List<Policy> policies, List<Rule> rules) {
        this.name = name;
        this.level = level;
        this.policies = policies;
        this.rules = rules;
    }

    /**
     * Parser method for a RBAC Role object
     *
     * @param parser the XContentParser as received
     * @return A parsed Role object
     * @throws IOException rethrown from XContentParser methods
     */
    public static Role parse(XContentParser parser) throws IOException {
        String name = null;
        Long level = null;
        List<Policy> policies = null;
        List<Rule> rules = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken() == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case NAME:
                        name = parser.text();
                        break;
                    case LEVEL:
                        level = parser.longValue();
                        break;
                    case POLICIES:
                        XContentParserUtils.ensureExpectedToken(
                                XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                        policies = ParseUtils.parseArray(parser, Policy::parse);
                        break;
                    case RULES:
                        XContentParserUtils.ensureExpectedToken(
                                XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                        rules = ParseUtils.parseArray(parser, Rule::parse);
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }
        return new Role(name, level, policies, rules);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject();
        builder.field(NAME, this.name);
        builder.field(LEVEL, this.level);
        builder.array(POLICIES, this.policies);
        builder.array(RULES, this.rules);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "Role{"
                + "name='"
                + name
                + '\''
                + ", level="
                + level
                + ", policies="
                + policies
                + ", rules="
                + rules
                + '}';
    }
}
