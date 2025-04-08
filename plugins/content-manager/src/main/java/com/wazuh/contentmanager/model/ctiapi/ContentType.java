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

public enum ContentType {
    CREATE("create"),
    UPDATE("update"),
    DELETE("delete");

    /** The string value of the type. */
    private final String value;

    /**
     * Constructs a new ContentType with the specified string value.
     *
     * @param value the string value of the type
     */
    ContentType(String value) {
        this.value = value;
    }

    /**
     * Gets the string value of the type.
     *
     * @return the string value of the type
     */
    public String getValue() {
        return value;
    }

    /**
     * Converts a string to the corresponding ContentType enum.
     *
     * @param value the string value to convert
     * @return the corresponding ContentType enum
     * @throws IllegalArgumentException if the string does not match any ContentType
     */
    public static ContentType fromString(String value) {
        for (ContentType type : ContentType.values()) {
            if (type.value.equalsIgnoreCase(value)) {
                return type;
            }
        }
        throw new IllegalArgumentException("Invalid type: " + value);
    }

    @Override
    public String toString() {
        return value;
    }
}
