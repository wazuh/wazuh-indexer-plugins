/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonValue;

import java.util.Locale;

/**
 * Enum representing the content spaces managed by the Content Manager plugin. Each space defines a
 * different access level or content state for CTI resources.
 */
public enum Space {
    /** Standard content space for production-ready CTI resources. */
    STANDARD,

    /** Custom content space for user-defined CTI resources. */
    CUSTOM,

    /** Draft content space for content under development. */
    DRAFT,

    /** Testing content space for experimental or testing resources. */
    TEST;

    /**
     * Returns the lowercase string representation of the space.
     *
     * @return The space name in lowercase.
     */
    @JsonValue
    @Override
    public String toString() {
        return this.name().toLowerCase(Locale.ROOT);
    }

    /**
     * Compares the enum value with a given string representation.
     *
     * @param s The string to compare with.
     * @return True if the string matches the enum value (case-insensitive), false otherwise.
     */
    public boolean equals(String s) {
        return this.toString().equalsIgnoreCase(s);
    }

    /**
     * Provides the next space to which the current space can transition to. Only DRAFT and TEST
     * spaces can be promoted.
     *
     * <pre>
     *  - DRAFT -> TEST
     *  - TEST -> CUSTOM
     * </pre>
     *
     * @return the next space transition.
     */
    public Space promote() {
        return switch (this) {
            case DRAFT -> TEST;
            case TEST -> CUSTOM;
            default -> this;
        };
    }

    @JsonCreator
    public static Space fromValue(String value) {
        for (Space space : Space.values()) {
            if (space.toString().equalsIgnoreCase(value)) {
                return space;
            }
        }
        throw new IllegalArgumentException("Unknown space: [" + value + "].");
    }
}
