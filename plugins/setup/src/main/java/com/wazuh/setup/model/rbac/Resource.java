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

/** Model class for a Resource object */
public class Resource implements ToXContentObject {

    private final String resourceString;

    /**
     * Constructor for a Resource @TODO: We need to split a resource into its constituent parts
     *
     * @param resourceString A string in the shape "*:*:*" describing a resource
     */
    public Resource(String resourceString) {
        this.resourceString = resourceString;
    }

    /**
     * Parser for a Resource object
     *
     * @param parser A XContentParser to attach a Resource object to
     * @return A parsed Resource object
     * @throws IOException thrown if the token is not a parseable string
     */
    public static Resource parse(XContentParser parser) throws IOException {
        if (!parser.nextToken().isValue()) {
            throw new IOException("Resource value expected");
        }
        return new Resource(parser.text());
    }

    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        return builder.value(this.resourceString);
    }
}
