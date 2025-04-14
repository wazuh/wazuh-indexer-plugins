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
package com.wazuh.contentmanager.util;

import com.google.gson.JsonObject;
import com.google.gson.JsonParser;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.ToXContentObject;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

public class XContentHelper {

    /**
     * Converts a ToXContentObject to a JsonObject.
     *
     * @param content the ToXContentObject to convert.
     * @return the converted JsonObject.
     * @throws IOException if an error occurs during conversion.
     */
    public static JsonObject xContentObjectToJson(ToXContentObject content) throws IOException {
        XContentBuilder builder = XContentFactory.jsonBuilder();
        content.toXContent(builder, ToXContent.EMPTY_PARAMS);
        return JsonParser.parseString(builder.toString()).getAsJsonObject();
    }

    /**
     * Converts a JsonObject to a ToXContentObject.
     *
     * @param content the JsonObject to convert.
     * @return the converted ToXContentObject.
     * @throws IOException if an error occurs during conversion.
     */
    public static XContentParser getParser(JsonObject content) throws IOException {
        return XContentType.JSON
                .xContent()
                .createParser(
                        NamedXContentRegistry.EMPTY,
                        DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                        content.toString());
    }

    /**
     * Converts a byte array to a ToXContentObject.
     *
     * @param content the byte array to convert.
     * @return the converted ToXContentObject.
     * @throws IOException if an error occurs during conversion.
     */
    public static XContentParser getParser(byte[] content) throws IOException {
        return XContentType.JSON
                .xContent()
                .createParser(
                        NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, content);
    }
}
