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
 *   <li>When referencing from another class, used static qualifiers: {@code Constants.KEY_HASH}.</li>
 *   <li>Use common sense. Keep this file clean and organized.</li>
 * </ul>
 */
// spotless:on
public class Constants {
    // REST API responses. Pattern: <type>_<http_status_code>_<name>. Type is: E for error, S for
    // success.
    public static final String S_200_PROMOTION_COMPLETED = "Promotion completed successfully.";
    public static final String E_400_INVALID_REQUEST_BODY = "Invalid request body.";
    public static final String E_400_MISSING_FIELD = "Missing [%s] field.";
    public static final String E_400_INVALID_FIELD_FORMAT = "Invalid '%s' format.";
    public static final String E_400_RESOURCE_NOT_FOUND = "%s [%s] not found.";
    public static final String E_400_RESOURCE_NOT_IN_DRAFT = "%s with ID '%s' is not in draft space.";
    public static final String E_400_RESOURCE_SPACE_INVALID = "Invalid space value.";
    public static final String E_400_RESOURCE_SPACE_MISMATCH =
            "Invalid space value. Must be one of: %s.";
    public static final String E_400_INVALID_UUID = "'%s' is not a valid UUID.";
    public static final String E_400_INTEGRATION_HAS_RESOURCES =
            "Cannot delete integration because it has %s attached.";
    public static final String E_400_INVALID_PROMOTION_OPERATION_FOR_POLICY =
            "Only 'update' operation is supported for policy.";
    public static final String E_400_UNPROMOTABLE_SPACE = "Space [%s] cannot be promoted.";
    public static final String E_400_DUPLICATE_NAME =
            "A %s with the name '%s' already exists in the %s space.";
    public static final String E_400_UUID_SHOULD_NOT_BE_PROVIDED =
            "ID should not be provided in the payload.";
    public static final String E_400_ENGINE_VALIDATION_FAILED = "Engine validation failed.";
    public static final String E_400_CANNOT_REMOVE_ROOT_DECODER =
            "Cannot remove decoder [%s] as it is set as root decoder.";
    public static final String E_400_INVALID_SPACE =
            "Logtest is only supported for the 'test' and 'standard' spaces. Received space: '%s'.";
    public static final String E_400_INTEGRATION_NOT_FOUND =
            "Integration [%s] not found in the '%s' space.";
    public static final String E_404_RESOURCE_NOT_FOUND = "Resource not found.";
    public static final String E_500_INTERNAL_SERVER_ERROR = "Internal Server Error.";
    public static final String E_SECURITY_ANALYTICS_ERROR =
            "Error in Security Analytics."; // Used for both BAD_REQUEST and INTERNAL_SERVER_ERROR
    public static final String E_500_MISSING_DRAFT_POLICY = "Draft policy not found.";
    public static final String E_500_VERSION_NOT_FOUND = "Unable to determine current Wazuh version.";
    public static final String E_500_CTI_UNREACHABLE =
            "Unable to reach the CTI API to check for updates.";

    // Log messages
    public static final String I_LOG_SUCCESS = "{} {} successfully (id={})";
    public static final String D_LOG_OPERATION = "{} {} (id={})";
    public static final String E_LOG_ENGINE_IS_NULL = "Engine instance unavailable.";
    public static final String E_LOG_INDEX_NOT_FOUND = "Index [{}] not found.";
    public static final String E_LOG_SAP_SYNC_FAILED = "Failed to sync {} in Security Analytics: {}";
    public static final String E_LOG_OPERATION_FAILED = "Error {} {}: {}";
    public static final String E_LOG_FAILED_TO = "Failed to {} {} (id={}): {}";
    public static final String E_LOG_UNEXPECTED = "Unexpected error {} {} (id={}): {}";
    public static final String E_LOG_MISSING_FIELD = "Missing '{}' field.";
    public static final String E_LOG_MISSING_OBJECT = "Missing '{}' object.";
    public static final String W_LOG_VALIDATION_FAILED = "Validation failed: {}";
    public static final String W_LOG_OPERATION_FAILED = "{} failed for {}: {}";
    public static final String W_LOG_OPERATION_FAILED_ID = "{} failed for {} [{}]: {}";
    public static final String W_LOG_RESOURCE_NOT_FOUND = "{} [{}] not found.";
    public static final String W_LOG_EXTERNAL_NOT_FOUND =
            "Resource {} [{}] not found in external service, continuing deletion.";
    public static final String I_LOG_SAP_SEND = "Sending {} [{}] with ID [{}] to Security Analytics.";
    public static final String I_LOG_SAP_DELETED = "{} deleted successfully (document.id={}{}).";
    public static final String I_LOG_SAP_DELETE_ASYNC =
            "Sending delete request for {} to Security Analytics (document.id={}{}).";

    // Index Constants
    public static final String INDEX_POLICIES = "wazuh-threatintel-policies";
    public static final String INDEX_INTEGRATIONS = "wazuh-threatintel-integrations";
    public static final String INDEX_RULES = "wazuh-threatintel-rules";
    public static final String INDEX_KVDBS = "wazuh-threatintel-kvdbs";
    public static final String INDEX_DECODERS = "wazuh-threatintel-decoders";
    public static final String INDEX_IOCS = "wazuh-threatintel-enrichments";
    public static final String INDEX_CVES = "wazuh-threatintel-vulnerabilities";
    public static final String INDEX_FILTERS = "wazuh-threatintel-filters";
    // Resource Types Keys
    public static final String KEY_POLICY = "policy";
    public static final String KEY_INTEGRATIONS = "integrations";
    public static final String KEY_KVDBS = "kvdbs";
    public static final String KEY_RULES = "rules";
    public static final String KEY_DECODERS = "decoders";
    public static final String KEY_IOCS = "iocs";
    public static final String KEY_CVES = "cves";
    public static final String KEY_FILTERS = "filters";
    public static final String KEY_ENRICHMENTS = "enrichments";

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
    public static final String KEY_OFFSET = "offset";
    public static final String KEY_ENABLED = "enabled";
    public static final String KEY_TITLE = "title";
    public static final String KEY_DESCRIPTION = "description";
    public static final String KEY_UPDATING = "updating";
    public static final String KEY_PAYLOAD = "payload";
    public static final String KEY_STATUS = "status";
    public static final String KEY_INPUT = "input";

    // Newly added keys for ResourceMetadata
    public static final String KEY_REFERENCES = "references";
    public static final String KEY_DOCUMENTATION = "documentation";
    public static final String KEY_COMPATIBILITY = "compatibility";
    public static final String KEY_SUPPORTS = "supports";

    // Enrichment types allowed in policy
    public static final String E_400_INVALID_ENRICHMENT =
            "Invalid enrichment type '%s'. Allowed values are: %s";
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
    public static final String KEY_FILTER = "filter";

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
    public static final String TYPE_PREFILTER = "pre-filter";
    public static final String TYPE_POSTFILTER = "post-filter";

    // Resources Indices Mapping for space-aware resources (used by SpaceService for promotion).
    // Note: IoCs and CVEs are NOT included here because they use flat storage without spaces.
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
                    KEY_FILTERS,
                    INDEX_FILTERS);

    // Snapshot constants
    public static final String PLUGIN_DIR_NAME = "wazuh-indexer-content-manager";
    public static final String CTI_SNAPSHOTS_DIR = "snapshots";
    public static final String CONTENT_SNAPSHOT_FILENAME = "ruleset.zip";
    public static final String IOC_SNAPSHOT_FILENAME = "ioc.zip";
    public static final String CVE_SNAPSHOT_FILENAME = "cve.zip";

    // IOC type hashes
    public static final String IOC_TYPE_HASHES_ID = "__ioc_type_hashes__";
    public static final String KEY_TYPE_HASHES = "type_hashes";

    // Queries
    public static final String Q_DOCUMENT_TYPE = "document.type";
    public static final String Q_SPACE_NAME = "space.name";
    public static final String Q_DOCUMENT_ID = "document.id";
    public static final String Q_DOCUMENT_ENABLED = "document.enabled";
    public static final String Q_DOCUMENT_TITLE = "document.metadata.title";
    public static final String Q_HASH = "hash.sha256";
    public static final String Q_HITS = "hits";

    // IOC export
    public static final String IOC_EXPORT_FILENAME = "iocs.ndjson";
    public static final String I_LOG_IOC_EXPORT_COMPLETE = "IOC export completed: {}";
    public static final String E_LOG_IOC_EXPORT_FAILED = "Failed to export IOCs to NDJSON: {}";
    public static final String I_LOG_IOC_ENGINE_NOTIFIED =
            "Engine notified to load IOCs with reply: {}";
    public static final String E_LOG_IOC_ENGINE_NOTIFY_FAILED =
            "Failed to notify Engine to load IOCs: {}";
    public static final String W_LOG_IOC_ENGINE_BUSY =
            "Engine is currently processing a previous IOC update, skipping notification.";
    public static final String W_LOG_IOC_STATE_CHECK_FAILED =
            "Failed to check Engine IOC state, skipping notification: {}";

    // Operations
    public static final String KEY_OPERATION = "operation";
    public static final String KEY_CHANGES = "changes";
    public static final String OP_ADD = "add";
    public static final String OP_REMOVE = "remove";
    public static final String OP_UPDATE = "update";
}
