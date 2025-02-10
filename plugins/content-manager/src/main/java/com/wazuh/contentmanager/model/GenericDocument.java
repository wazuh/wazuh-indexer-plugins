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
package com.wazuh.contentmanager.model;

import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;

import java.io.IOException;
import java.util.Map;

public class GenericDocument implements ToXContentObject {
    public static final String SOURCE = "_source";

    private String id;
    private Map<String, Object> source;

    public GenericDocument(String id, Map<String, Object> source) {
        this.id = id;
        this.source = source;
    }

    /**
     * Builds an GenericDocument XContentBuilder. Iterates over the args map adding key-value pairs
     *
     * @param builder This is received from the parent object
     * @param params Not used
     * @return A complete args XContentBuilder object
     * @throws IOException rethrown from XContentBuilder objects within
     */
    @Override
    public XContentBuilder toXContent(XContentBuilder builder, Params params) throws IOException {
        builder.field("id", this.id);
        builder.startObject(GenericDocument.SOURCE);
        for (String key : this.source.keySet()) {
            builder.field(key, this.source.get(key));
        }
        return builder.endObject();
    }
}
