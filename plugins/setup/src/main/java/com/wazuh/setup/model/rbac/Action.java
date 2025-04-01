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

import java.io.IOException;

/** Model class for an Action object */
public class Action implements ToXContentObject {

    private final String target;
    private final String permission;

    /**
     * Constructor for an Action object
     *
     * @param target the action target (e.g. agent, node, group, etc.)
     * @param permission the permission to be applied (e.g. read, write run, etc.)
     */
    public Action(String target, String permission) {
        this.target = target;
        this.permission = permission;
    }

    /**
     * Parser for an Action object
     *
     * @param parser An XContentParser to attach an Action object to
     * @return A parsed Action object
     * @throws IOException thrown if the token is not a parseable string
     */
    public static Action parse(XContentParser parser) throws IOException {
        if (!parser.nextToken().isValue()) {
            throw new IOException("Action value expected");
        }
        String[] value = parser.text().split(":");
        return new Action(value[0], value[1]);
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.value(String.format("%s:%s", this.target, this.permission));
    }

    @Override
    public String toString() {
        return "Action{" + "target='" + target + '\'' + ", permission='" + permission + '\'' + '}';
    }
}
