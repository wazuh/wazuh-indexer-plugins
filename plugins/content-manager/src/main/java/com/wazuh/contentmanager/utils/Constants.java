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

import com.wazuh.contentmanager.cti.catalog.index.CredentialsIndex;

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
    public static final String S_201_ACCESS_TOKEN_RECEIVED = "Access token received successfully.";
    public static final String E_400_INVALID_REQUEST_BODY = "Invalid request body.";
    public static final String E_400_MISSING_FIELD = "Missing [%s] field.";
    public static final String E_400_INVALID_FIELD_FORMAT = "Invalid '%s' format.";
    public static final String E_400_RESOURCE_NOT_FOUND = "%s [%s] not found.";
    public static final String E_400_RESOURCE_NOT_IN_DRAFT = "%s with ID '%s' is not in draft space.";
    public static final String E_400_RESOURCE_SPACE_INVALID = "Invalid space value.";
    public static final String E_400_RESOURCE_SPACE_MISMATCH =
            "Invalid space value. Must be one of: %s.";
    public static final String E_400_INVALID_ENRICHMENT =
            "Invalid enrichment type '%s'. Allowed values are: %s";
    public static final String E_400_DUPLICATE_ENRICHMENT = "Duplicate enrichment type '%s'.";
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
            "Logtest is only supported for the 'test', 'custom' and 'standard' spaces. Received space: '%s'.";
    public static final String E_400_INTEGRATION_NOT_FOUND =
            "Integration [%s] not found in the '%s' space.";
    public static final String E_404_RESOURCE_NOT_FOUND = "Resource not found.";
    public static final String E_412_UNPROTECTED_CREDENTIALS_INDEX =
            "Registration is disabled because the '"
                    + CredentialsIndex.INDEX_NAME
                    + "' index is not configured as a system index. "
                    + "Add it to plugins.security.system_indices.indices in opensearch.yml and restart.";
    public static final String E_403_UPDATE_ON_DEMAND_DISABLED =
            "On-demand content updates are disabled on this deployment.";
    public static final String E_403_POLICY_UPDATE_DISABLED =
            "Policy updates are disabled on this deployment.";
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
    public static final String D_LOG_SAP_SEND = "Sending {} [{}] with ID [{}] to Security Analytics.";
    public static final String D_LOG_SAP_DELETED = "{} deleted successfully (document.id={}{}).";
    public static final String D_LOG_SAP_DELETE_ASYNC =
            "Sending delete request for {} to Security Analytics (document.id={}{}).";
    public static final String I_LOG_SAP_SUMMARY =
            "Sent {} of {} {} to Security Analytics for space [{}].";
    public static final String W_LOG_SAP_PARTIAL =
            "{} {} could not be sent to Security Analytics for space [{}]: {}";
    public static final String I_LOG_ACCESS_TOKEN_REMOVED =
            "Access token removed successfully. Environment is now unregistered.";
    public static final String I_LOG_ACCESS_TOKEN_SET =
            "Access token stored successfully. Registration will be confirmed on next plan retrieval.";
    public static final String I_LOG_ACCESS_TOKEN_EXPIRED_OR_INVALID =
            "Access token is invalid or expired. Clearing credentials and falling back to public plan.";

    // Log messages - consumer synchronization (AbstractConsumerService)
    public static final String D_LOG_SYNC_COMPLETED =
            "Synchronization completed for consumer [{}]. Updated: {}";
    public static final String D_LOG_CONSUMER_DOC_ABSENT =
            "Consumer [{}] doc not present; skipping status update to [{}]";
    public static final String D_LOG_CONSUMER_STATUS_SET = "Consumer [{}] status set to [{}]";
    public static final String W_LOG_CONSUMER_STATUS_FAILED =
            "Failed to set consumer [{}] status to [{}]: {}";
    public static final String D_LOG_CONSUMER_RESOURCE_READ_FAILED =
            "Could not read existing consumer resource for [{}]: {}";
    public static final String D_LOG_CONSUMER_T0_WRITTEN =
            "Recorded initial state for consumer [{}] (status UPDATING, local offset 0, remote offset {}).";
    public static final String W_LOG_CONSUMER_T0_FAILED =
            "Failed to write initial consumer state for [{}]: {}";
    public static final String W_LOG_REFRESH_INDICES_FAILED = "Error refreshing indices: {}";
    public static final String D_LOG_SNAPSHOTS_DIR_RESOLVE_FAILED =
            "Could not resolve snapshots directory for [{}]: {}";
    public static final String D_LOG_INDEX_SWAP_STARTED =
            "Data source for consumer [{}] changed from [{}] to [{}]; rebuilding in staging indices.";
    public static final String D_LOG_INDEX_SWAP_TO_FREE_PLAN =
            "Consumer [{}] reverted to the default data source (was [{}], now [{}]); rebuilding in staging indices.";
    public static final String I_LOG_CONTENT_SOURCE_CHANGED =
            "Data source changed for consumer [{}]; updating content.";
    public static final String D_LOG_SIGNED_URL_RESOLVER =
            "Consumer [{}] is registered; using signed download URLs.";
    public static final String D_LOG_REGULAR_URL_RESOLVER =
            "Consumer [{}] is not registered; using public download URLs.";
    public static final String E_LOG_INDEX_CREATE_FAILED = "Failed to create index [{}]: {}";
    public static final String W_LOG_LOCAL_OFFSET_EXCEEDS_REMOTE =
            "Local offset [{}] exceeds remote offset [{}] for consumer [{}]. Resetting.";
    public static final String W_LOG_LOCAL_SNAPSHOT_CHECK_FAILED =
            "Failed to check local snapshot at [{}]: {}";
    public static final String E_LOG_CLEAR_RESOURCES_FAILED =
            "Failed to clear existing resources for consumer [{}] during snapshot initialization: {}";
    public static final String D_LOG_SNAPSHOT_INIT_CUSTOM_URL =
            "Initializing snapshot from custom consumer URL: {}";
    public static final String W_LOG_REMOTE_SNAPSHOT_FAILED_FALLBACK =
            "Remote snapshot initialization failed for consumer [{}]. Falling back to local snapshot [{}].";
    public static final String W_LOG_LOCAL_SNAPSHOT_FALLBACK_FAILED =
            "Local snapshot fallback failed for consumer [{}].";
    public static final String W_LOG_REMOTE_SNAPSHOT_FAILED_NO_LOCAL =
            "Remote snapshot initialization failed for consumer [{}] and no local snapshot was found at [{}].";
    public static final String W_LOG_CATALOG_UNREACHABLE_FALLBACK =
            "Could not reach catalog URL [{}] for consumer [{}]. Falling back to local snapshot [{}].";
    public static final String D_LOG_INIT_FROM_LOCAL_SNAPSHOT =
            "Initializing consumer [{}] from local snapshot [{}]";
    public static final String E_LOG_LOCAL_SNAPSHOT_INIT_FAILED =
            "Local snapshot initialization failed for consumer [{}].";
    public static final String E_LOG_INIT_FAILED_NO_LOCAL_NO_REMOTE_REACH =
            "Could not initialize consumer [{}]: no local snapshot at [{}] and the remote source could not be reached. Content will be retried on the next sync.";
    public static final String E_LOG_INIT_FAILED_NO_LOCAL_NO_REMOTE_CONFIG =
            "Could not initialize consumer [{}]: no local snapshot at [{}] and no remote source is configured.";
    public static final String I_LOG_UPDATING_CONSUMER_CONTENT =
            "Updating consumer [{}] content (offset {} → {}).";
    public static final String E_LOG_MANIFEST_NOT_FOUND =
            "Snapshot manifest not found at [{}]; consumer cannot be initialized and will be retried on the next sync.";
    public static final String E_LOG_MANIFEST_ENTRY_MISSING =
            "No snapshot entry for [{}] in manifest [{}]; consumer cannot be initialized and will be retried on the next sync.";
    public static final String D_LOG_SNAPSHOT_DETAILS_LOADED =
            "Snapshot details for [{}] loaded from [{}].";
    public static final String E_LOG_MANIFEST_READ_FAILED =
            "Failed to read snapshot manifest from [{}]: {}. Consumer cannot be initialized and will be retried on the next sync.";
    public static final String D_LOG_NO_PLAN_RETURNED =
            "No plan returned for registered environment.";
    public static final String D_LOG_NO_FEATURE_FOR_CONSUMER =
            "No feature found for consumer type [{}] in plan [{}].";
    public static final String D_LOG_PLAN_PROVIDES_RESOURCE =
            "Plan [{}] provides resource [{}] for consumer [{}].";
    public static final String W_LOG_PLAN_RESOURCE_RESOLVE_FAILED =
            "Failed to resolve plan resource for consumer [{}]: {}";
    public static final String E_LOG_SHADOW_SWAP_UNAVAILABLE =
            "Cannot rebuild content for consumer [{}]: the remote content source is unavailable.";
    public static final String D_LOG_SHADOW_INDICES_CREATING =
            "Creating staging indices to rebuild content for consumer [{}].";
    public static final String D_LOG_SHADOW_SNAPSHOT_DOWNLOADING =
            "Downloading the new content into staging indices for consumer [{}] from [{}].";
    public static final String E_LOG_SHADOW_SNAPSHOT_FAILED =
            "Failed to download the new content for consumer [{}]; keeping the current content.";
    public static final String D_LOG_REINDEX_USER_CONTENT =
            "Copying custom content into the staging indices for consumer [{}].";
    public static final String D_LOG_ATOMIC_ALIAS_SWAP =
            "Switching aliases to the new content indices for consumer [{}].";
    public static final String E_LOG_SHADOW_SWAP_FAILED_BEFORE_SWAP =
            "Failed to rebuild content in staging indices for consumer [{}]: {}. Cleaning up.";
    public static final String D_LOG_CONSUMER_DOC_REWRITTEN =
            "Updated consumer [{}] record to the new content source [{}] (offset {}).";
    public static final String E_LOG_CONSUMER_DOC_REWRITE_FAILED =
            "Content for consumer [{}] was switched over but its record could not be saved: {}. It will be retried on the next sync.";
    public static final String W_LOG_OLD_INDICES_DELETE_FAILED =
            "Failed to remove the previous content indices for consumer [{}]: {}";
    public static final String I_LOG_CONTENT_UPDATED_NEW_SOURCE =
            "Content updated to the new source for consumer [{}].";

    // Log messages - Security Analytics sync (SecurityAnalyticsServiceImpl, ConsumerRulesetService)
    public static final String D_LOG_SAP_DETECTOR_DELETED_THEN_INTEGRATION =
            "Detector [{}] deleted. Now deleting integration.";
    public static final String D_LOG_SAP_DETECTOR_NO_ENABLED_RULES =
            "Detector [{}] has no enabled rules. Skipping creation.";
    public static final String W_LOG_DETECTOR_INTERVAL_OUT_OF_BOUNDS =
            "Interval for detector [{}] is out of bounds ([{},{}], got: {}). Falling back to default value of {} minutes.";
    public static final String D_LOG_DETECTOR_FILTERED_DISABLED_RULES =
            "Filtered {} disabled rule(s) from detector rule list";
    public static final String E_LOG_FETCH_ENABLED_RULES_FAILED =
            "Failed to fetch enabled rule IDs: {}";
    public static final String E_LOG_EVALUATE_RULES_FAILED =
            "Failed to evaluate rules via Security Analytics transport action.";
    public static final String W_LOG_SAP_SPACE_DELETE_PARTIAL =
            "Partial failures deleting Security Analytics resources for space [{}]: {}";
    public static final String I_LOG_SAP_SPACE_DELETED =
            "Deleted [{}] integrations and [{}] rules from Security Analytics for space [{}]";
    public static final String I_LOG_ENGINE_STANDARD_LOADED =
            "Engine load for standard space completed successfully.";
    public static final String W_LOG_ENGINE_STANDARD_LOAD_STATUS =
            "Engine load for standard space returned status [{}]: {}";
    public static final String E_LOG_ENGINE_STANDARD_LOAD_FAILED =
            "Failed to load standard space into Engine: {}";
    public static final String E_LOG_SAP_INDEX_MISSING =
            "{} index is missing. Cannot sync {} to Security Analytics Plugin.";
    public static final String D_LOG_SAP_NOTHING_TO_SYNC =
            "No {} to synchronize with the Security Analytics plugin.";
    public static final String D_LOG_SAP_ITEM_FAILED =
            "{} [{}] could not be sent to Security Analytics: {}";
    public static final String W_LOG_SAP_SYNC_TIMEOUT =
            "Timed out sending {} to Security Analytics; some may be unavailable until the next sync.";
    public static final String E_LOG_SAP_SYNC_INTERRUPTED =
            "Interrupted while sending {} to the Security Analytics plugin: {}";
    public static final String E_LOG_SAP_SYNC_UNEXPECTED =
            "Unexpected error sending {} to the Security Analytics plugin: {}";
    public static final String D_LOG_SAP_DETECTORS_SYNCING =
            "Syncing {} detectors ({} sequentially, {} in parallel)";
    public static final String E_LOG_DETECTOR_WAIT_INTERRUPTED =
            "Interrupted while waiting for detector sync to complete.";
    public static final String W_LOG_HIT_MISSING_DOCUMENT =
            "Hit [{}] missing 'document' field, skipping";

    // Log messages - snapshot / update / IOC (SnapshotServiceImpl, UpdateServiceImpl,
    // ConsumerIocService)
    public static final String W_LOG_SNAPSHOT_URL_EMPTY =
            "Snapshot URL is empty. Skipping initialization.";
    public static final String D_LOG_SNAPSHOT_INIT_START =
            "Starting snapshot initialization for [{}]";
    public static final String E_LOG_SNAPSHOT_DOWNLOAD_FAILED = "Failed to download snapshot from {}";
    public static final String D_LOG_SNAPSHOT_WAIT_PENDING_BULK =
            "Waiting for pending bulk updates to finish...";
    public static final String E_LOG_SNAPSHOT_PROCESS_FAILED = "Error processing snapshot: {}";
    public static final String D_LOG_SNAPSHOT_NO_INDEX_FOR_TYPE =
            "No ContentIndex found for type [{}]. Skipping.";
    public static final String D_LOG_SNAPSHOT_PARSE_LINE_FAILED =
            "Error parsing/indexing JSON line: {}";
    public static final String W_LOG_SNAPSHOT_ENTRIES_SKIPPED =
            "Skipped {} snapshot entries (missing payload: {}, unknown type: {}, unmapped type: {}, parse errors: {}).";
    public static final String E_LOG_SNAPSHOT_READ_FILE_FAILED =
            "Error reading snapshot file [{}]: {}";
    public static final String D_LOG_SNAPSHOT_LOCAL_INIT_START =
            "Starting local snapshot initialization for [{}] from [{}]";
    public static final String E_LOG_SNAPSHOT_LOCAL_PROCESS_FAILED =
            "Error processing local snapshot: {}";
    public static final String W_LOG_SNAPSHOT_CONSUMER_DOC_MISSING =
            "Consumer [{}] record not found after loading the snapshot; skipping local offset update.";
    public static final String E_LOG_SNAPSHOT_CONSUMER_STATE_UPDATE_FAILED =
            "Failed to update consumer state in {}: {}";
    public static final String D_LOG_SNAPSHOT_LOCAL_DELETED = "Deleted local snapshot file [{}]";
    public static final String W_LOG_SNAPSHOT_LOCAL_DELETE_FAILED =
            "Failed to delete local snapshot file [{}]: {}";
    public static final String W_LOG_SNAPSHOT_TEMP_FILE_DELETE_FAILED =
            "Failed to delete temp file {}";
    public static final String W_LOG_SNAPSHOT_CLEANUP_FAILED = "Error during cleanup: {}";
    public static final String D_LOG_UPDATE_START =
            "Starting content update for consumer [{}] from [{}] to [{}]";
    public static final String E_LOG_UPDATE_FETCH_CHANGES_FAILED = "Failed to fetch changes: {} {}";
    public static final String E_LOG_UPDATE_APPLY_OFFSET_FAILED =
            "Failed to apply offset [{}] (type={}, resource={}): {}";
    public static final String I_LOG_UPDATE_CONSUMER_SUCCESS =
            "Successfully updated consumer [{}] to offset [{}]";
    public static final String E_LOG_UPDATE_FAILED = "Error during content update: {}";
    public static final String W_LOG_UPDATE_NO_INDEX_FOR_TYPE = "No index mapped for type [{}]";
    public static final String D_LOG_UPDATE_SKIP_CVE_DELETE =
            "Skipping DELETE for CVE resource [{}] (CVE removals are not applied).";
    public static final String W_LOG_UPDATE_UNSUPPORTED_OPERATION =
            "Unsupported JSON patch operation [{}]";
    public static final String W_LOG_UPDATE_RESET_CONSUMER =
            "Resetting consumer [{}] offset to 0 due to update failure.";
    public static final String E_LOG_UPDATE_RESET_CONSUMER_FAILED = "Failed to reset consumer: {}";
    public static final String D_LOG_IOC_EXPORT_SKIPPED_TEST_ENV =
            "IOCs export skipped: test environment";
    public static final String D_LOG_IOC_TYPE_HASHES_STORED = "IOC type hashes stored successfully.";
    public static final String E_LOG_IOC_TYPE_HASHES_FAILED =
            "Failed to compute and store IOC type hashes: {}";
    public static final String D_LOG_IOC_ENGINE_REPLY = "Engine reply to IOC load request: {}";

    // Log messages - space / index / index swap (SpaceService, ContentIndex, IndexSwapHelper)
    public static final String E_LOG_DELETE_SPACE_RESOURCES_FAILED =
            "Failed to delete space resources for [{}]: {}";
    public static final String I_LOG_SPACE_INITIALIZED = "Initialized space [{}]";
    public static final String D_LOG_SPACE_ALREADY_INITIALIZED =
            "Space [{}] already initialized, skipping.";
    public static final String E_LOG_INITIALIZE_SPACE_FAILED = "Failed to initialize space [{}]: {}";
    public static final String W_LOG_FETCH_RESOURCE_TYPE_FAILED =
            "Failed to fetch [{}] from index [{}] for space [{}]: {}";
    public static final String E_LOG_CONSOLIDATE_RESOURCES_FAILED =
            "Failed to consolidate resources: {}";
    public static final String E_LOG_FETCH_RESOURCES_FAILED =
            "Failed to fetch resources from [{}] for space [{}]: {}";
    public static final String E_LOG_GET_DOCUMENT_FAILED =
            "Failed to get document [{}] from index [{}]: {}";
    public static final String E_LOG_GET_POLICY_FAILED = "Failed to get policy for space [{}]: {}";
    public static final String W_LOG_DOCUMENT_NOT_FOUND_FOR_DELETION =
            "Document with document.id [{}] not found in space [{}] for deletion";
    public static final String E_LOG_DELETE_RESOURCES_FAILED = "Failed to delete resources: {}";
    public static final String E_LOG_FIND_DOCUMENT_ID_FAILED =
            "Error finding document ID for space [{}] and docId [{}]: {}";
    public static final String W_LOG_POLICY_INDEX_MISSING =
            "Policy index [{}] does not exist. Skipping hash calculation.";
    public static final String D_LOG_RECALCULATING_HASH =
            "Recalculating content hash for policy [{}] in space [{}].";
    public static final String E_LOG_BULK_UPDATE_HASHES_FAILED =
            "Bulk update of policy space hashes failed: {}";
    public static final String I_LOG_CONTENT_HASH_CHANGED = "Content hash changed for space(s) {}.";
    public static final String E_LOG_CALCULATE_HASHES_FAILED = "Error calculating policy hashes: {}";
    public static final String W_LOG_RETRIEVE_DOCUMENT_FAILED =
            "Failed to retrieve document [{}] from index [{}]: {}";
    public static final String W_LOG_IOC_TYPE_HASHES_NOT_FOUND =
            "IOC type hashes document not found. Enrichment validation may fail.";
    public static final String E_LOG_RETRIEVE_ENRICHMENT_TYPES_FAILED =
            "Failed to retrieve valid enrichment types from IOC index: {}";
    public static final String W_LOG_CHECK_ENGINE_RESOURCES_FAILED =
            "Failed to check engine resources in space [{}] index [{}]: {}";
    public static final String E_LOG_CREATE_INDEX_NO_MAPPINGS =
            "Cannot create index [{}]: Mappings path not provided.";
    public static final String D_LOG_INDEX_CREATED_WITH_ALIAS = "Index [{}] created with alias [{}].";
    public static final String E_LOG_CREATE_SHADOW_INDEX_NO_MAPPINGS =
            "Cannot create staging index [{}]: mappings path not provided.";
    public static final String D_LOG_SHADOW_INDEX_CREATED =
            "Created staging index [{}] (hidden, no alias).";
    public static final String E_LOG_MAPPINGS_FILE_NOT_FOUND =
            "Could not find mappings file [{}] for index [{}]";
    public static final String E_LOG_READ_MAPPINGS_FAILED =
            "Could not read mappings for index [{}]: {}";
    public static final String E_LOG_INDEX_DOCUMENT_FAILED = "Failed to index document [{}]: {}";
    public static final String D_LOG_DELETED_FROM_INDEX = "Deleted {} from {}";
    public static final String E_LOG_DELETE_DOCUMENT_FAILED = "Failed to delete {}: {}";
    public static final String D_LOG_NO_DOCUMENT_FOUND_QUERY =
            "No document found in [{}] with query {}";
    public static final String E_LOG_SEARCH_BY_QUERY_FAILED = "Search by query failed in [{}]: {}";
    public static final String W_LOG_BULK_INDEXING_FAILURES =
            "Bulk indexing finished with failures: {}";
    public static final String E_LOG_BULK_INDEX_OPERATION_FAILED = "Bulk index operation failed: {}";
    public static final String E_LOG_SEMAPHORE_INTERRUPTED =
            "Interrupted while waiting for semaphore: {}";
    public static final String E_LOG_CLEAR_INDEX_NO_MAPPINGS =
            "Cannot clear index [{}]: mappings path not set.";
    public static final String D_LOG_INDEX_WIPED_RECREATED =
            "[{}] cleared and recreated (backing index [{}]).";
    public static final String E_LOG_CLEAR_INDEX_FAILED = "[{}] clear failed: {}";
    public static final String E_LOG_PROCESS_PAYLOAD_FAILED =
            "Failed to process payload via models: {}";
    public static final String D_LOG_SHADOW_INDEX_CREATED_FOR_ALIAS =
            "Created staging index [{}] for alias [{}].";
    public static final String D_LOG_REINDEX_USER_CONTENT_START =
            "Copying custom content from [{}] to [{}].";
    public static final String D_LOG_REINDEX_USER_CONTENT_COMPLETE =
            "Finished copying custom content from [{}] to [{}].";
    public static final String D_LOG_ALIAS_SWAP_COMPLETED =
            "Switched {} aliases to the new content indices.";
    public static final String D_LOG_DELETED_PHYSICAL_INDEX = "Removed previous content index [{}].";
    public static final String W_LOG_DELETE_PHYSICAL_INDEX_FAILED =
            "Failed to remove previous content index [{}]: {}";

    // Log messages - CTI console / Engine socket / job runner
    public static final String W_LOG_CTI_REGISTRATION_FAILED =
            "Registration on the Wazuh Console failed.";
    public static final String D_LOG_CTI_REGISTRATION_DETAIL =
            "Wazuh Console registration response (HTTP {}): {}";
    public static final String E_LOG_CTI_ACCESS_TOKEN_FAILED =
            "Could not obtain an access token from the Wazuh Console.";
    public static final String D_LOG_CTI_ACCESS_TOKEN_DETAIL = "Wazuh Console access-token error: {}";
    public static final String E_LOG_CTI_ACCESS_TOKEN_PARSE_FAILED =
            "Could not parse the response from the Wazuh Console to obtain an access token.";
    public static final String W_LOG_RESOURCE_NULL_OR_EMPTY = "Resource must not be null or empty";
    public static final String W_LOG_ACCESS_TOKEN_NULL_OR_EMPTY =
            "Access token must not be null or empty";
    public static final String W_LOG_CTI_RESOURCE_TOKEN_FAILED =
            "Resource token exchange with the Wazuh Console failed.";
    public static final String D_LOG_CTI_RESOURCE_TOKEN_RESPONSE_DETAIL =
            "Wazuh Console resource-token response (HTTP {}): {}";
    public static final String E_LOG_CTI_RESOURCE_TOKEN_FAILED =
            "Could not obtain a resource token from the Wazuh Console.";
    public static final String D_LOG_CTI_RESOURCE_TOKEN_DETAIL =
            "Wazuh Console resource-token error: {}";
    public static final String E_LOG_CTI_RESOURCE_TOKEN_PARSE_FAILED =
            "Could not parse the response from the Wazuh Console to obtain a resource token.";
    public static final String D_LOG_CTI_ACCESS_TOKEN_UPDATED = "Wazuh Console access token updated.";
    public static final String E_LOG_ENGINE_SOCKET_UNAVAILABLE =
            "Cannot reach the Wazuh Engine: its API socket is not available. Verify the Engine is running.";
    public static final String D_LOG_ENGINE_SOCKET_NOT_FOUND = "Engine socket not found at [{}].";
    public static final String E_LOG_ENGINE_TIMEOUT =
            "Timed out communicating with the Wazuh Engine: {}";
    public static final String E_LOG_ENGINE_PERMISSION_DENIED =
            "Permission denied accessing the Wazuh Engine socket. Check the socket file permissions.";
    public static final String E_LOG_ENGINE_COMMUNICATION_FAILED =
            "Failed to communicate with the Wazuh Engine: {}";
    public static final String E_LOG_ENGINE_UNEXPECTED_ERROR =
            "Unexpected error communicating with the Wazuh Engine: {}";
    public static final String W_LOG_ENGINE_STATUS_LINE_PARSE_FAILED =
            "Could not parse the status line of the Wazuh Engine response; assuming HTTP 500.";
    public static final String D_LOG_ENGINE_RESPONSE_HEADERS = "Wazuh Engine response headers: {}";
    public static final String W_LOG_ENGINE_JSON_PARSE_FAILED =
            "Could not parse the Wazuh Engine JSON response.";
    public static final String D_LOG_ENGINE_RESPONSE_BODY = "Wazuh Engine response body: {}";
    public static final String I_LOG_JOB_HANDLER_REGISTERED =
            "Scheduled job handler registered for type [{}].";
    public static final String W_LOG_JOB_UNEXPECTED_TYPE =
            "Received an unexpected scheduled job type; skipping.";
    public static final String D_LOG_JOB_DELEGATING =
            "Delegating scheduled job of type [{}] to its handler.";
    public static final String E_LOG_JOB_EXECUTION_FAILED = "Error executing job [{}]: {}";
    public static final String W_LOG_JOB_NO_HANDLER =
            "No handler registered for scheduled job type [{}]; skipping.";

    // Log messages - plugin startup / REST promote (ContentManagerPlugin, RestPostPromoteAction,
    // AbstractContentAction)
    public static final String W_LOG_CREDENTIALS_INDEX_NOT_PROTECTED =
            "[{}] index is not configured as a system index. Registration will be disabled and any stored token will be removed on startup. Add it to plugins.security.system_indices.indices in opensearch.yml and ensure plugins.security.system_indices.enabled is true, then restart.";
    public static final String D_LOG_SKIP_CATALOG_SYNC_TRIGGER = "Skipping catalog sync job trigger";
    public static final String I_LOG_PLUGIN_INDEX_CREATED = "Index created: {} acknowledged={}";
    public static final String E_LOG_PLUGIN_INDEX_CREATE_FAILED =
            "Failed to create {} index, due to: {}";
    public static final String E_LOG_PLUGIN_INIT_FAILED = "Error during plugin initialization: {}";
    public static final String W_LOG_ACCESS_TOKEN_DELETED_UNPROTECTED =
            "Deleted stored access token because the credentials index is not configured as a system index.";
    public static final String I_LOG_CTI_TOKEN_LOADED =
            "Wazuh Console access token loaded from credentials index.";
    public static final String D_LOG_CREDENTIALS_INDEX_NO_TOKEN =
            "Credentials index exists but no access token is stored.";
    public static final String D_LOG_CREDENTIALS_INDEX_MISSING =
            "Credentials index does not exist yet; access token not loaded.";
    public static final String W_LOG_CTI_TOKEN_LOAD_FAILED =
            "Could not load the Wazuh Console access token from the credentials index: {}";
    public static final String I_LOG_JOB_INDEX_CREATED = "Created job index {}.";
    public static final String D_LOG_INDEX_ALREADY_EXISTS = "Index {} already exists. Skipping.";
    public static final String W_LOG_INDEX_CREATE_FAILED = "Could not create index {}: {}";
    public static final String I_LOG_CATALOG_SYNC_JOB_SCHEDULED =
            "Catalog Sync Job scheduled successfully.";
    public static final String W_LOG_CATALOG_SYNC_JOB_FAILED =
            "Failed to schedule Catalog Sync Job: {}, retrying";
    public static final String E_LOG_JOB_SCHEDULE_GIVE_UP =
            "Giving up scheduling {} after {} attempts.";
    public static final String I_LOG_JOB_SCHEDULE_RETRY = "Retrying {} (attempt {}/{}) in {}s.";
    public static final String D_LOG_TELEMETRY_JOB_DISABLED =
            "Telemetry job is disabled via settings. Skipping registration.";
    public static final String I_LOG_TELEMETRY_JOB_SCHEDULED =
            "Telemetry Ping Job scheduled successfully (Interval: 1d).";
    public static final String W_LOG_TELEMETRY_JOB_FAILED =
            "Failed to schedule Telemetry Ping Job: {}";
    public static final String I_LOG_TELEMETRY_DYNAMICALLY_ENABLED =
            "Telemetry setting dynamically enabled. Scheduling job and triggering initial run...";
    public static final String I_LOG_TELEMETRY_DYNAMICALLY_DISABLED =
            "Telemetry setting dynamically disabled. Removing job...";
    public static final String I_LOG_TELEMETRY_JOB_REMOVED =
            "Telemetry Ping Job removed successfully.";
    public static final String E_LOG_TELEMETRY_JOB_REMOVE_FAILED =
            "Failed to remove Telemetry Ping Job: {}";
    public static final String W_LOG_VERSION_FIELD_MISSING =
            "VERSION.json found but 'version' field is empty or missing.";
    public static final String W_LOG_VERSION_READ_FAILED = "Could not read VERSION.json: {}";
    public static final String D_LOG_ENGINE_REJECTED_PAYLOAD =
            "Engine rejected promotion payload: {}";
    public static final String D_LOG_ENGINE_VALIDATION_COMPLETE =
            "Engine validation for space [{}] completed successfully.";
    public static final String W_LOG_SNAPSHOT_OLD_VERSION_FAILED =
            "Failed to snapshot old version of [{}] in [{}]: {}";
    public static final String E_LOG_SNAPSHOT_DELETE_TARGET_FAILED =
            "Failed to snapshot delete target [{}] in [{}]: {}. Aborting promotion.";
    public static final String W_LOG_RESOURCE_NOT_IN_TARGET_SPACE =
            "Resource '{}' to delete is in space '{}', not target space '{}'";
    public static final String D_LOG_RESOURCE_MARKED_FOR_DELETION =
            "Resource '{}' marked for deletion in target space {}";
    public static final String E_LOG_CONSOLIDATION_FAILED = "Consolidation failed, rolling back: {}";
    public static final String W_LOG_SAP_DELETE_RESOURCE_FAILED =
            "Failed to delete {} [{}] from Security Analytics for space [{}]: {}";
    public static final String W_LOG_SAP_SYNC_RESOURCE_FAILED =
            "Failed to sync {} [{}] to Security Analytics for space [{}]: {}";
    public static final String I_LOG_ROLLBACK_START =
            "Rolling back promotion to space [{}] ({} steps).";
    public static final String D_LOG_ROLLBACK_STEP_OK = "Rollback step OK: {}";
    public static final String E_LOG_ROLLBACK_STEP_FAILED =
            "Rollback step FAILED [{}]. Index: [{}], Affected IDs: {}. Manual intervention required. Error: {}";
    public static final String I_LOG_ROLLBACK_COMPLETE =
            "Rollback completed for promotion to space [{}].";
    public static final String D_LOG_SAP_ROLLBACK_DELETED =
            "Security Analytics rollback: deleted {} [{}] from space [{}]";
    public static final String D_LOG_SAP_ROLLBACK_RESTORED =
            "Security Analytics rollback: restored {} [{}] in space [{}]";
    public static final String W_LOG_SAP_ROLLBACK_FAILED =
            "Security Analytics rollback failed for {} [{}]: {}";
    public static final String D_LOG_SAP_ROLLBACK_RESTORED_DELETED =
            "Security Analytics rollback: restored deleted {} [{}] in space [{}]";
    public static final String W_LOG_SAP_ROLLBACK_RESTORE_DELETED_FAILED =
            "Security Analytics rollback failed to restore deleted {} [{}]: {}";
    public static final String E_LOG_PROCESS_REQUEST_FAILED = "Failed to process content request: {}";
    public static final String E_LOG_SEND_ERROR_RESPONSE_FAILED = "Failed to send error response";

    // Index Constants
    public static final String INDEX_POLICIES = "wazuh-threatintel-policies";
    public static final String INDEX_INTEGRATIONS = "wazuh-threatintel-integrations";
    public static final String INDEX_RULES = "wazuh-threatintel-rules";
    public static final String INDEX_KVDBS = "wazuh-threatintel-kvdbs";
    public static final String INDEX_DECODERS = "wazuh-threatintel-decoders";
    public static final String INDEX_IOCS = "wazuh-threatintel-enrichments";
    public static final String INDEX_CVES = ".wazuh-threatintel-vulnerabilities";
    public static final String INDEX_FILTERS = "wazuh-threatintel-filters";

    // Index settings
    public static final String KEY_INDEX_CODEC = "index.codec";
    public static final String CODEC_ZSTD = "zstd";
    public static final String KEY_INDEX_REFRESH_INTERVAL = "index.refresh_interval";
    public static final String REFRESH_INTERVAL_DISABLED = "-1";

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
    public static final String KEY_DETECTOR = "detector";
    public static final String KEY_SOURCE = "source";
    public static final String KEY_INTERVAL = "interval";
    public static final String KEY_TITLE = "title";
    public static final String KEY_DESCRIPTION = "description";
    public static final String KEY_UPDATING = "updating";
    public static final String KEY_PAYLOAD = "payload";
    public static final String KEY_MESSAGE = "message";
    public static final String KEY_STATUS = "status";
    public static final String KEY_INPUT = "input";
    public static final String KEY_YAML = "yaml";

    // Newly added keys for ResourceMetadata
    public static final String KEY_REFERENCES = "references";
    public static final String KEY_DOCUMENTATION = "documentation";
    public static final String KEY_COMPATIBILITY = "compatibility";
    public static final String KEY_SUPPORTS = "supports";

    // Consumer's metadata
    public static final String KEY_IS_PUBLIC = "is_public";
    public static final String KEY_CONTEXT = "context";
    public static final String KEY_LOCAL_OFFSET = "local_offset";
    public static final String KEY_REMOTE_OFFSET = "remote_offset";

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
    public static final String IOC_SNAPSHOT_FILENAME = "iocs.zip";
    public static final String CVE_SNAPSHOT_FILENAME = "vulnerabilities.zip";
    public static final String MANIFEST_FILENAME = "manifest.json";

    // HTTP headers
    public static final String USER_AGENT_PREFIX = "Wazuh Indexer ";

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
    public static final String D_LOG_IOC_EXPORT_COMPLETE = "IOC export completed: {}";
    public static final String E_LOG_IOC_EXPORT_FAILED = "Failed to export IOCs to NDJSON: {}";
    public static final String I_LOG_IOC_ENGINE_NOTIFIED =
            "Notified the Wazuh Engine to load the updated IOCs.";
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

    // Job Scheduler registration retries
    public static final int MAX_JOB_SCHEDULE_RETRIES = 3;
    public static final int JOB_SCHEDULE_RETRY_BACKOFF_SECONDS = 15;

    // Setup plugin readiness marker (written by the Setup plugin once all its
    // index templates, indices and data streams have been created).
    public static final String INDEX_SETUP_STATUS = ".wazuh-setup-status";
    public static final String SETUP_STATUS_DOC_ID = "setup-status";
    public static final String SETUP_STATUS_COMPLETE = "complete";
    public static final int MAX_SETUP_WAIT_RETRIES = 3;
    public static final int SETUP_WAIT_BACKOFF_BASE_SECONDS = 5;
}
