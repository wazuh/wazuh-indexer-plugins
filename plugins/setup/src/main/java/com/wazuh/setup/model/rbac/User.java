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
import java.util.ArrayList;
import java.util.List;

/** Model class for individual changes within a consumer changes reply */
public class User implements ToXContentObject {

    private static final String USER = "user";
    private static final String ID = "id";
    private static final String NAME = "name";
    private static final String PASSWORD = "password";
    private static final String ALLOW_RUN_AS = "allow_run_as";
    private static final String CREATED_AT = "created_at";
    private static final String ROLES = "roles";

    private final String id;
    private final String name;
    private final String password;
    private final Boolean allowRunAs;
    private final Long createdAt;
    private final List<Role> roles;

    /**
     * Constructor of the class
     *
     * @param id User ID
     * @param name User Name
     * @param password Password Hash
     * @param allowRunAs Whether run_as is permitted
     * @param createdAt Creation date as a Unix Timestamp
     * @param roles an array of Role objects
     */
    public User(
            String id,
            String name,
            String password,
            Boolean allowRunAs,
            Long createdAt,
            List<Role> roles) {
        this.id = id;
        this.name = name;
        this.password = password;
        this.allowRunAs = allowRunAs;
        this.createdAt = createdAt;
        this.roles = roles;
    }

    private static List<Role> parseRolesArray(XContentParser parser) throws IOException {
        List<Role> array = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            switch (parser.currentToken()) {
                case START_OBJECT:
                    array.add(Role.parse(parser));
                    break;
                default:
                    parser.skipChildren();
            }
        }

        return array;
    }

    /**
     * Parser method for a RBAC User object
     *
     * @param parser the XContentParser as received
     * @return A parsed User object
     * @throws IOException rethrown from XContentParser methods
     */
    public static User parse(XContentParser parser) throws IOException {
        String id = null;
        String name = null;
        String password = null;
        Boolean allowRunAs = null;
        Long createdAt = null;
        List<Role> roles = null;
        while (parser.nextToken() != XContentParser.Token.END_OBJECT) {
            if (parser.currentToken() == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken();
                switch (fieldName) {
                    case ID:
                        id = parser.text();
                        break;
                    case NAME:
                        name = parser.text();
                        break;
                    case PASSWORD:
                        password = parser.text();
                        break;
                    case ALLOW_RUN_AS:
                        allowRunAs = parser.booleanValue();
                        break;
                    case CREATED_AT:
                        createdAt = parser.longValue();
                        break;
                    case ROLES:
                        XContentParserUtils.ensureExpectedToken(
                                XContentParser.Token.START_OBJECT, parser.currentToken(), parser);
                        roles = parseRolesArray(parser);
                        break;
                    default:
                        parser.skipChildren();
                        break;
                }
            }
        }
        return new User(id, name, password, allowRunAs, createdAt, roles);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.startObject(USER);
        builder.field(ID, this.id);
        builder.field(NAME, this.name);
        builder.field(PASSWORD, this.password);
        builder.field(ALLOW_RUN_AS, this.allowRunAs);
        builder.field(CREATED_AT, this.createdAt);
        builder.array(ROLES, this.roles);
        return builder.endObject();
    }

    @Override
    public String toString() {
        return "User{"
                + "id='"
                + id
                + '\''
                + ", name='"
                + name
                + '\''
                + ", password='"
                + password
                + '\''
                + ", allowRunAs="
                + allowRunAs
                + ", createdAt="
                + createdAt
                + ", roles="
                + roles
                + '}';
    }
}
