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
package com.wazuh.contentmanager.utils;

/**
 * Common constants used across Content Manager REST services.
 */
public final class ContentManagerConstants {

    // Index names
    public static final String INTEGRATION_INDEX = ".cti-integrations";
    public static final String DECODER_INDEX = ".cti-decoders";
    public static final String KVDB_INDEX = ".cti-kvdbs";

    // ID prefix
    public static final String INDEX_ID_PREFIX = "d_";

    // Resource types
    public static final String DECODER_TYPE = "decoder";
    public static final String KVDB_TYPE = "kvdb";

    // Common field names
    public static final String FIELD_INTEGRATION = "integration";
    public static final String FIELD_RESOURCE = "resource";
    public static final String FIELD_ID = "id";
    public static final String FIELD_DOCUMENT = "document";
    public static final String FIELD_TYPE = "type";
    public static final String FIELD_SPACE = "space";
    public static final String FIELD_NAME = "name";
    public static final String FIELD_METADATA = "metadata";
    public static final String FIELD_AUTHOR = "author";
    public static final String FIELD_DATE = "date";
    public static final String FIELD_MODIFIED = "modified";

    // Resource-specific field names
    public static final String FIELD_DECODERS = "decoders";
    public static final String FIELD_KVDBS = "kvdbs";

    private ContentManagerConstants() {
        // Utility class, prevent instantiation
    }
}
