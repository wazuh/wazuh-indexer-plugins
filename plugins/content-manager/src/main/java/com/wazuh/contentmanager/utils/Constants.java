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

import java.util.Map;

/**
 * Central and unified storage for constants used by the plugin. Follow these guidelines:
 *
 * <ul>
 *   <li>Use uppercase letters only.
 *   <li>Separate words with underscores.
 *   <li>Log strings end with a dot.
 *   <li>Index names are prefixed with <i>INDEX<i/>.
 *   <li>Map keys are prefixed with <i>KEY</i>.
 *   <li>Response strings for the HTTP API are prefixed with the type of message and status code.
 *   <li>When referencing from another class, used static qualifiers: <code>Constants.KEY_HASH
 *       </code>.
 *   <li>Use common sense. Keep this file clean and organized.
 * </ul>
 */
public class Constants {
    // REST API responses. Pattern: <type>_<http_status_code>_<name>. Type is: E for error, S for
    // success.
    public static final String E_500_ENGINE_INSTANCE_IS_NULL = "Engine instance is null.";
    public static final String E_400_JSON_REQUEST_BODY_IS_REQUIRED = "JSON request body is required.";
    public static final String E_400_INVALID_JSON_CONTENT = "Invalid JSON content.";
    public static final String E_400_INVALID_PROMOTION_OPERATION_FOR_POLICY =
            "Only 'update' operation is supported for policy.";
    public static final String E_400_UNPROMOTABLE_SPACE = "Space [%s] cannot be promoted.";

    // Index Constants
    public static final String INDEX_POLICIES = ".cti-policies";
    public static final String INDEX_INTEGRATIONS = ".cti-integrations";
    public static final String INDEX_RULES = ".cti-rules";
    public static final String INDEX_KVDBS = ".cti-kvdbs";
    public static final String INDEX_DECODERS = ".cti-decoders";
    public static final String INDEX_FILTERS = ".engine-filters";

    // Resource Types Keys
    public static final String KEY_POLICY = "policy";
    public static final String KEY_INTEGRATIONS = "integrations";
    public static final String KEY_KVDBS = "kvdbs";
    public static final String KEY_RULES = "rules";
    public static final String KEY_DECODERS = "decoders";
    public static final String KEY_FILTERS = "filters";

    // Resource Metadata Keys
    public static final String KEY_DOCUMENT = "document";
    public static final String KEY_HASH = "hash";
    public static final String KEY_SPACE = "space";

    // Resources Indices Mapping. Output: Key -> Index Name
    public static final Map<String, String> RESOURCE_INDICES =
            Map.of(
                    KEY_POLICY, INDEX_POLICIES,
                    KEY_INTEGRATIONS, INDEX_INTEGRATIONS,
                    KEY_RULES, INDEX_RULES,
                    KEY_KVDBS, INDEX_KVDBS,
                    KEY_DECODERS, INDEX_DECODERS,
                    KEY_FILTERS, INDEX_FILTERS);
}
