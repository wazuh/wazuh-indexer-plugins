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

import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;

/** Interface to handle parsing Arrays generically */
@FunctionalInterface
public interface ParserFunction<T> {

    /**
     * Function to call parse() on generic objects
     *
     * @param parser the XContentParser to append to
     * @return a T object
     * @throws IOException rethrown from XContentParser methods
     */
    T parse(XContentParser parser) throws IOException;
}
