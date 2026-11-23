/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.setup.model;

/**
 * Result of comparing the schema version an index was created with against the versions the shipped
 * template declares.
 *
 * <p>Every template carries a {@code schema_version}, the release that last changed it, and a
 * {@code compat_version}, the oldest schema version whose indices can still be upgraded in place.
 * The index inherits the template's {@code _meta} when it is created, so its own {@code
 * schema_version} says which template it was built from.
 */
public enum SchemaStatus {
    /** The index was created from the shipped template. */
    UP_TO_DATE("up_to_date"),

    /** The index is older than the shipped template, but its mappings can be updated in place. */
    UPGRADE_IN_PLACE("upgrade_in_place"),

    /** The index is older than the template's compatibility version and must be rebuilt. */
    REBUILD_REQUIRED("rebuild_required");

    private final String value;

    SchemaStatus(String value) {
        this.value = value;
    }

    /**
     * Returns the value stored in the status index.
     *
     * @return the snake_case name of the status.
     */
    public String getValue() {
        return this.value;
    }

    /**
     * Returns the status stored under a value.
     *
     * @param value the stored value.
     * @return the matching status.
     * @throws IllegalArgumentException if no status has that value.
     */
    public static SchemaStatus fromValue(String value) {
        for (SchemaStatus status : SchemaStatus.values()) {
            if (status.value.equals(value)) {
                return status;
            }
        }
        throw new IllegalArgumentException("Unknown schema status [" + value + "]");
    }

    /**
     * Classifies an index.
     *
     * <p>An index at the shipped version, or newer, is up to date: a newer index can only come from a
     * package downgrade, which is not supported, and the plugin leaves it alone. An index at or above
     * the compatibility version can be upgraded in place. Any older index, including one with no
     * version at all (version {@code 0}), must be rebuilt.
     *
     * @param installed schema version the index carries, {@code 0} when it carries none.
     * @param shipped schema version of the shipped template.
     * @param compat compatibility version of the shipped template.
     * @return the status of the index.
     */
    public static SchemaStatus classify(long installed, long shipped, long compat) {
        if (installed >= shipped) {
            return UP_TO_DATE;
        }
        if (installed >= compat) {
            return UPGRADE_IN_PLACE;
        }
        return REBUILD_REQUIRED;
    }
}
