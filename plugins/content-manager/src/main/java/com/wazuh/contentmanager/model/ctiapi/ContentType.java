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
package com.wazuh.contentmanager.model.ctiapi;

import java.util.Locale;

/**
 * Enum representing the type of content changes. This enum is used to specify the type of content
 * changes that can occur in the system. The possible values are: CREATE: Represents a creation
 * operation. UPDATE: Represents an update operation. DELETE: Represents a deletion operation.
 */
public enum ContentType {
    CREATE,
    UPDATE,
    DELETE;

    /**
     * Converts a string to the corresponding ContentType enum.
     *
     * @param value the string value to convert
     * @return the corresponding ContentType enum
     * @throws IllegalArgumentException if the string does not match any ContentType
     */
    public static ContentType fromString(String value) {
        for (ContentType type : ContentType.values()) {
            if (type.toString().equalsIgnoreCase(value.toUpperCase(Locale.ROOT))) {
                return type;
            }
        }
        throw new IllegalArgumentException("Invalid type: " + value);
    }
}
