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
package com.wazuh.setup.utils;

import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.wazuh.setup.model.rbac.ParserFunction;

/** Helper class for parsing arrays of objects in a generic fashion */
public class ParseUtils {

    /**
     * Method for parsing arrays of objects of generic types
     *
     * @param parser The XContentParser to read the array into
     * @param parserFunction The function that will handle the arrayed objects
     * @param <T> They type of objects within the list
     * @return A List of objects of type T
     * @throws IOException rethrown from XContentParser methods
     */
    public static <T> List<T> parseArray(XContentParser parser, ParserFunction<T> parserFunction)
            throws IOException {
        List<T> array = new ArrayList<>();
        while (parser.nextToken() != XContentParser.Token.END_ARRAY) {
            if (parser.currentToken() == XContentParser.Token.START_OBJECT) {
                array.add(parserFunction.parse(parser));
            } else {
                parser.skipChildren();
            }
        }
        return array;
    }
}
