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
import java.util.Set;

// spotless:off
/**
 * Central and unified storage for constants used by the plugin. Follow these guidelines:
 *
 * <ul>
 *   <li>Use uppercase letters only.</li>
 *   <li>Separate words with underscores.</li>
 *   <li>Log strings end with a dot.</li>
 *   <li>Index names are prefixed with <i>INDEX</i>.</li>
 *   <li>Map keys are prefixed with <i>KEY</i>.</li>
 *   <li>Response strings for the HTTP API are prefixed with the type of message and status code.</li>
 *   <li>When referencing from another class, used static qualifiers: <code>Constants.KEY_HASH</code>.</li>
 *   <li>Use common sense. Keep this file clean and organized.</li>
 * </ul>
 */
// spotless:on
public class Constants {
    // REST API responses. Pattern: <type>_<http_status_code>_<name>. Type is: E for error, S for
    // success.
    public static final String E_400_INVALID_REQUEST_BODY = "Invalid request body.";
    public static final String E_400_MISSING_FIELD = "Missing [%s] field.";
    public static final String E_400_INVALID_FIELD_FORMAT = "Invalid '%s' format.";
    public static final String E_400_RESOURCE_NOT_FOUND = "%s [%s] not found.";
    public static final String E_400_RESOURCE_NOT_IN_DRAFT = "%s with ID '%s' is not in draft space.";
    public static final String E_500_INTERNAL_SERVER_ERROR = "Internal Server Error.";
    public static final String E_400_INVALID_UUID = "'%s' is not a valid UUID.";
    public static final String E_404_RESOURCE_NOT_FOUND = "Resource not found.";
    public static final String E_400_INTEGRATION_HAS_RESOURCES =
            "Cannot delete integration because it has %s attached.";
    public static final String E_400_INVALID_PROMOTION_OPERATION_FOR_POLICY =
            "Only 'update' operation is supported for policy.";
    public static final String E_400_UNPROMOTABLE_SPACE = "Space [%s] cannot be promoted.";
    public static final String S_200_PROMOTION_COMPLETED = "Promotion completed successfully.";
    public static final String E_400_DUPLICATE_NAME =
            "A %s with the name '%s' already exists in the %s space.";

    // Log messages
    public static final String E_LOG_ENGINE_IS_NULL = "Engine instance unavailable.";
    public static final String E_LOG_ENGINE_VALIDATION = "Engine validation failed: {}";
    public static final String E_LOG_INDEX_NOT_FOUND = "Index [{}] not found.";
    public static final String E_LOG_OPERATION_FAILED = "Error {} {}: {}";
    public static final String E_LOG_FAILED_TO = "Failed to {} {} (id={}): {}";
    public static final String E_LOG_UNEXPECTED = "Unexpected error {} {} (id={}): {}";
    public static final String W_LOG_VALIDATION_ERROR = "Validation error during {}: {}";
    public static final String I_LOG_SUCCESS = "{} {} successfully (id={})";
    public static final String D_LOG_OPERATION = "{} {} (id={})";
    public static final String W_LOG_OPERATION_FAILED = "{} failed for {}: {}";
    public static final String W_LOG_OPERATION_FAILED_ID = "{} failed for {} [{}]: {}";
    public static final String W_LOG_RESOURCE_NOT_FOUND = "{} [{}] not found.";
    public static final String W_LOG_EXTERNAL_NOT_FOUND =
            "Resource {} [{}] not found in external service, continuing deletion.";

    // Index Constants
    public static final String INDEX_POLICIES = ".cti-policies";
    public static final String INDEX_INTEGRATIONS = ".cti-integrations";
    public static final String INDEX_RULES = ".cti-rules";
    public static final String INDEX_KVDBS = ".cti-kvdbs";
    public static final String INDEX_DECODERS = ".cti-decoders";
    public static final String INDEX_IOCS = ".cti-iocs";
    public static final String INDEX_FILTERS = ".engine-filters";

    // Resource Types Keys
    public static final String KEY_POLICY = "policy";
    public static final String KEY_INTEGRATIONS = "integrations";
    public static final String KEY_KVDBS = "kvdbs";
    public static final String KEY_RULES = "rules";
    public static final String KEY_DECODERS = "decoders";
    public static final String KEY_IOCS = "iocs";
    public static final String KEY_FILTERS = "filters";

    // Resource Metadata Keys
    public static final String KEY_DOCUMENT = "document";
    public static final String KEY_HASH = "hash";
    public static final String KEY_SHA256 = "sha256";
    public static final String KEY_SPACE = "space";
    public static final String KEY_NAME = "name";
    public static final String KEY_ID = "id";
    public static final String KEY_DATE = "date";
    public static final String KEY_METADATA = "metadata";
    public static final String KEY_AUTHOR = "author";
    public static final String KEY_MODIFIED = "modified";
    public static final String KEY_ENABLED = "enabled";
    public static final String KEY_TITLE = "title";
    public static final String KEY_DESCRIPTION = "description";

    // Enrichment types allowed in policy
    public static final Set<String> ALLOWED_ENRICHMENT_TYPES =
            Set.of("file", "domain-name", "ip", "url", "geo");
    public static final String E_400_INVALID_ENRICHMENT =
            "Invalid enrichment type '%s'. Allowed values are: file, domain-name, ip, url, geo.";
    public static final String E_400_DUPLICATE_ENRICHMENT = "Duplicate enrichment type '%s'.";

    // API request content fields
    public static final String KEY_TYPE = "type";
    public static final String KEY_RESOURCE = "resource";
    public static final String KEY_INTEGRATION = "integration";
    public static final String KEY_KVDB = "kvdb";
    public static final String KEY_DECODER = "decoder";
    public static final String KEY_RULE = "rule";
    public static final String KEY_LOGSOURCE = "logsource";
    public static final String KEY_PRODUCT = "product";
    public static final String KEY_CATEGORY = "category";

    // Engine promotion payload keys
    public static final String KEY_RESOURCES = "resources";
    public static final String KEY_FULL_POLICY = "full_policy";
    public static final String KEY_PROMOTE = "load_in_tester";

    // Resource Types
    public static final String TYPE_POLICY = "policy";
    public static final String TYPE_INTEGRATION = "integration";
    public static final String TYPE_RULE = "rule";
    public static final String TYPE_KVDB = "kvdb";
    public static final String TYPE_DECODER = "decoder";
    public static final String TYPE_IOC = "ioc";
    public static final String TYPE_FILTER = "filter";

    // Resources Indices Mapping. Output: Key -> Index Name
    public static final Map<String, String> RESOURCE_INDICES =
            Map.of(
                    KEY_POLICY,
                    INDEX_POLICIES,
                    KEY_INTEGRATIONS,
                    INDEX_INTEGRATIONS,
                    KEY_RULES,
                    INDEX_RULES,
                    KEY_KVDBS,
                    INDEX_KVDBS,
                    KEY_DECODERS,
                    INDEX_DECODERS,
                    KEY_IOCS,
                    INDEX_IOCS,
                    KEY_FILTERS,
                    INDEX_FILTERS);

    // Queries
    public static final String Q_SPACE_NAME = "space.name";
    public static final String Q_DOCUMENT_ID = "document.id";
    public static final String Q_DOCUMENT_TITLE = "document.title";
    public static final String Q_HASH = "hash.sha256";
    public static final String Q_HITS = "hits";

    // Operations
    public static final String KEY_OPERATION = "operation";
    public static final String KEY_CHANGES = "changes";
    public static final String OP_ADD = "add";
    public static final String OP_REMOVE = "remove";
    public static final String OP_UPDATE = "update";
}
