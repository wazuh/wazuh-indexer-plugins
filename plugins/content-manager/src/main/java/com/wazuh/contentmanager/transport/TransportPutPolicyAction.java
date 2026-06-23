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
package com.wazuh.contentmanager.transport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.time.Instant;
import java.util.*;

import com.wazuh.contentmanager.action.PutPolicyAction;
import com.wazuh.contentmanager.action.PutPolicyRequest;
import com.wazuh.contentmanager.action.PutPolicyResponse;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport action that performs a policy update. The work that mutates the standard/draft space is
 * gated here so the security plugin enforces {@link PutPolicyAction#NAME} as a cluster permission
 * and so the {@code plugins.content_manager.sensitive_config.locked} setting can block modification
 * entirely.
 *
 * <p>Engine loading is intentionally left to the caller (the REST handler owns the {@code
 * EngineService}); this action reports whether a reload is required via {@link
 * PutPolicyResponse#shouldReloadEngine()}.
 */
public class TransportPutPolicyAction
        extends HandledTransportAction<PutPolicyRequest, PutPolicyResponse> {
    private static final Logger log = LogManager.getLogger(TransportPutPolicyAction.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    private final Client client;
    private final SpaceService spaceService;
    private PayloadValidations payloadValidations = new PayloadValidations();

    @Inject
    public TransportPutPolicyAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            SpaceService spaceService) {
        super(PutPolicyAction.NAME, transportService, actionFilters, PutPolicyRequest::new);
        this.client = client;
        this.spaceService = spaceService;
    }

    /**
     * Test seam to override the payload validations.
     *
     * @param payloadValidations the payload validations instance to use.
     */
    void setPayloadValidations(PayloadValidations payloadValidations) {
        this.payloadValidations = payloadValidations;
    }

    @Override
    protected void doExecute(
            Task task, PutPolicyRequest request, ActionListener<PutPolicyResponse> listener) {
        // Lockdown gate: when enabled, sensitive configuration cannot be modified by anyone.
        if (PluginSettings.getInstance().isSensitiveConfigLocked()) {
            listener.onResponse(
                    new PutPolicyResponse(
                            Constants.E_403_SENSITIVE_CONFIG_LOCKED, RestStatus.FORBIDDEN, false));
            return;
        }

        String spaceName = request.getSpace();
        String payload = request.getPayload();

        // 1. Check request's payload exists
        if (payload == null || payload.isBlank()) {
            listener.onResponse(badRequest(Constants.E_400_INVALID_REQUEST_BODY));
            return;
        }

        SpaceService spaceService = this.spaceService;
        try {
            // Validate space parameter
            if (!Space.DRAFT.equals(spaceName) && !Space.STANDARD.equals(spaceName)) {
                listener.onResponse(
                        badRequest(
                                String.format(
                                        Locale.ROOT,
                                        Constants.E_400_RESOURCE_SPACE_MISMATCH,
                                        Space.DRAFT + ", " + Space.STANDARD)));
                return;
            }

            // 2. Validate request content
            JsonNode jsonContent;
            try {
                jsonContent = mapper.readTree(payload);
            } catch (IOException e) {
                listener.onResponse(badRequest(Constants.E_400_INVALID_REQUEST_BODY));
                return;
            }

            // Validate "resource"
            if (!jsonContent.has(Constants.KEY_RESOURCE)) {
                listener.onResponse(
                        badRequest(
                                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_RESOURCE)));
                return;
            }
            JsonNode resource = jsonContent.get(Constants.KEY_RESOURCE);
            log.debug(Constants.D_LOG_OPERATION, "Updating", Constants.KEY_POLICY, resource);
            Policy policy;
            try {
                policy = mapper.readValue(resource.toString(), Policy.class);
            } catch (IOException e) {
                listener.onResponse(badRequest(Constants.E_400_INVALID_REQUEST_BODY));
                return;
            }

            // Normalize empty root_decoder to null so it is omitted from serialization
            if (policy.getRootDecoder() != null && policy.getRootDecoder().isEmpty()) {
                policy.setRootDecoder(null);
            }

            // Validate required Policy fields
            List<String> missingFields = new ArrayList<>();
            if (policy.getEnabled() == null) {
                missingFields.add(Constants.KEY_ENABLED);
            }
            if (policy.getIndexUnclassifiedEvents() == null) {
                missingFields.add("index_unclassified_events");
            }
            if (policy.getIndexDiscardedEvents() == null) {
                missingFields.add("index_discarded_events");
            }

            // Draft space requires additional fields
            if (Space.DRAFT.equals(spaceName)) {
                if (policy.getAuthor() == null || policy.getAuthor().isEmpty()) {
                    missingFields.add(Constants.KEY_AUTHOR);
                }
                if (policy.getDescription() == null || policy.getDescription().isEmpty()) {
                    missingFields.add(Constants.KEY_DESCRIPTION);
                }
                if (policy.getDocumentation() == null) {
                    missingFields.add("documentation");
                }
                if (policy.getReferences() == null) {
                    missingFields.add("references");
                }
            }

            if (!missingFields.isEmpty()) {
                listener.onResponse(
                        badRequest(
                                String.format(
                                        Locale.ROOT, Constants.E_400_MISSING_FIELD, String.join(", ", missingFields))));
                return;
            }

            Set<String> knownEnrichmentTypes = spaceService.getKnownEnrichmentTypes();

            // Validate enrichments: only allowed values, no duplicates
            RestResponse enrichmentsValidationError =
                    this.payloadValidations.validateEnrichments(
                            policy.getEnrichments(), knownEnrichmentTypes);
            if (enrichmentsValidationError != null) {
                listener.onResponse(fromRestResponse(enrichmentsValidationError));
                return;
            }

            // 3. Update policy based on target space
            String policyId;
            if (Space.STANDARD.equals(spaceName)) {
                policyId = this.updateStandardPolicy(spaceService, policy);
            } else {
                policyId = this.updatePolicy(spaceService, policy);
            }

            // Regenerate space hash because space composition changed
            Set<String> changedSpaces = spaceService.calculateAndUpdate(List.of(spaceName));

            // Signal the caller to load the standard space into the Engine only if its hash changed
            boolean reloadEngine = changedSpaces.contains(Space.STANDARD.toString());

            listener.onResponse(new PutPolicyResponse(policyId, RestStatus.OK, reloadEngine));
        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            listener.onResponse(
                    new PutPolicyResponse(
                            Constants.E_400_INVALID_REQUEST_BODY + " " + e.getMessage(),
                            RestStatus.BAD_REQUEST,
                            false));
        } catch (Exception e) {
            log.error(
                    Constants.E_LOG_OPERATION_FAILED, "updating", Constants.KEY_POLICY, e.getMessage(), e);
            listener.onResponse(
                    new PutPolicyResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR + " " + e.getMessage(),
                            RestStatus.INTERNAL_SERVER_ERROR,
                            false));
        }
    }

    private static PutPolicyResponse badRequest(String message) {
        return new PutPolicyResponse(message, RestStatus.BAD_REQUEST, false);
    }

    private static PutPolicyResponse fromRestResponse(RestResponse response) {
        return new PutPolicyResponse(
                response.getMessage(), RestStatus.fromCode(response.getStatus()), false);
    }

    /**
     * Stores or updates the policy in the standard space.
     *
     * <p>Only the following fields from the incoming policy are applied: enrichments, filters,
     * enabled, index_unclassified_events, and index_discarded_events. All other fields are preserved
     * from the existing standard policy document.
     *
     * @param spaceService the space service bound to the current request's client.
     * @param incomingPolicy the incoming policy containing the fields to update.
     * @return the document ID of the persisted policy.
     * @throws IOException if storage fails.
     * @throws IllegalStateException if the standard policy document is not found.
     */
    @SuppressWarnings("unchecked")
    private String updateStandardPolicy(SpaceService spaceService, Policy incomingPolicy)
            throws IOException, IllegalStateException {
        // Get current standard policy
        Map<String, Object> currentPolicy = spaceService.getPolicy(Space.STANDARD.toString());
        Map<String, Object> currentPolicyDoc =
                (Map<String, Object>) currentPolicy.get(Constants.KEY_DOCUMENT);
        if (currentPolicyDoc == null) {
            throw new IllegalStateException(
                    Constants.E_500_INTERNAL_SERVER_ERROR + " Policy document not found in standard space.");
        }

        // Validate filters: allow reordering but prevent addition/removal
        List<String> currentFilters =
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_FILTERS, Collections.emptyList());
        List<String> newFilters = incomingPolicy.getFilters();

        RestResponse filtersValidationError =
                this.payloadValidations.validateListEquality(
                        currentFilters, newFilters, Constants.KEY_FILTERS);
        if (filtersValidationError != null) {
            throw new IllegalArgumentException(filtersValidationError.getMessage());
        }

        // Safekeep all unmodifiable values from the existing standard policy
        String docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();

        // Extract metadata from existing policy (now nested under "metadata", fallback to root)
        @SuppressWarnings("unchecked")
        Map<String, Object> existingMetadata =
                (Map<String, Object>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_METADATA, Collections.emptyMap());

        Object dateObj = existingMetadata.get(Constants.KEY_DATE);
        if (dateObj == null) dateObj = currentPolicyDoc.get(Constants.KEY_DATE);
        String docCreationDate = dateObj != null ? dateObj.toString() : "";

        // Build a policy preserving existing fields, only overriding the 5 allowed fields
        Policy mergedPolicy = new Policy();
        mergedPolicy.setId(docId);
        mergedPolicy.setDate(docCreationDate);
        mergedPolicy.setModified(Instant.now().toString());

        Object titleObj = existingMetadata.get(Constants.KEY_TITLE);
        if (titleObj == null) titleObj = currentPolicyDoc.get(Constants.KEY_TITLE);
        mergedPolicy.setTitle(titleObj != null ? titleObj.toString() : "");

        Object authorObj = existingMetadata.get(Constants.KEY_AUTHOR);
        if (authorObj == null) authorObj = currentPolicyDoc.get(Constants.KEY_AUTHOR);
        mergedPolicy.setAuthor(authorObj != null ? authorObj.toString() : "");

        Object descObj = existingMetadata.get(Constants.KEY_DESCRIPTION);
        if (descObj == null) descObj = currentPolicyDoc.get(Constants.KEY_DESCRIPTION);
        mergedPolicy.setDescription(descObj != null ? descObj.toString() : "");

        Object docObj = existingMetadata.get(Constants.KEY_DOCUMENTATION);
        if (docObj == null) docObj = currentPolicyDoc.get(Constants.KEY_DOCUMENTATION);
        mergedPolicy.setDocumentation(docObj != null ? docObj.toString() : "");

        Object refObj = existingMetadata.get(Constants.KEY_REFERENCES);
        if (refObj == null) refObj = currentPolicyDoc.get(Constants.KEY_REFERENCES);
        @SuppressWarnings("unchecked")
        List<String> existingReferences =
                (List<String>) (refObj != null ? refObj : Collections.emptyList());
        mergedPolicy.setReferences(existingReferences);

        Object compatObj = existingMetadata.get(Constants.KEY_COMPATIBILITY);
        if (compatObj == null) {
            compatObj = currentPolicyDoc.get(Constants.KEY_COMPATIBILITY);
        }
        @SuppressWarnings("unchecked")
        List<String> existingCompatibility =
                (List<String>) (compatObj != null ? compatObj : Collections.emptyList());
        mergedPolicy.getMetadata().setCompatibility(existingCompatibility);

        Object existingRootDecoder = currentPolicyDoc.get("root_decoder");
        String rootDecoderValue = existingRootDecoder != null ? existingRootDecoder.toString() : null;
        mergedPolicy.setRootDecoder(
                rootDecoderValue != null && !rootDecoderValue.isEmpty() ? rootDecoderValue : null);
        mergedPolicy.setIntegrations(
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyList()));

        // Apply the 5 modifiable fields from the incoming payload
        mergedPolicy.setEnrichments(incomingPolicy.getEnrichments());
        mergedPolicy.setFilters(incomingPolicy.getFilters());
        mergedPolicy.setEnabled(incomingPolicy.getEnabled());
        mergedPolicy.setIndexUnclassifiedEvents(incomingPolicy.getIndexUnclassifiedEvents());
        mergedPolicy.setIndexDiscardedEvents(incomingPolicy.getIndexDiscardedEvents());

        // Convert to JsonNode and persist.
        // Ensure metadata fields are stored only under document.metadata.
        ObjectNode policyNode = mapper.valueToTree(mergedPolicy);
        Resource.nestMetadataFields(policyNode);

        ContentIndex index = new ContentIndex(this.client, Constants.INDEX_POLICIES, null);
        try {
            ObjectNode document = mapper.createObjectNode();
            document.set(Constants.KEY_DOCUMENT, policyNode);
            ObjectNode spaceNode = mapper.createObjectNode();
            spaceNode.put(Constants.KEY_NAME, Space.STANDARD.toString());
            document.set(Constants.KEY_SPACE, spaceNode);
            String hash = Resource.computeSha256(policyNode.toString());
            ObjectNode hashNode = mapper.createObjectNode();
            hashNode.put(Constants.KEY_SHA256, hash);
            document.set(Constants.KEY_HASH, hashNode);
            String standardPolicyId =
                    spaceService.findDocumentId(Constants.INDEX_POLICIES, Space.STANDARD.toString(), docId);
            IndexResponse indexResponse = index.create(standardPolicyId, document);
            return indexResponse.getId();
        } catch (Exception e) {
            throw new IllegalStateException("Standard policy not found: " + e.getMessage());
        }
    }

    /**
     * Stores or updates the policy in the draft space.
     *
     * <p>If a draft policy already exists, it will be updated using its existing ID. Otherwise, a new
     * policy will be created with a generated UUID.
     *
     * @param spaceService the space service bound to the current request's client.
     * @param policy the policy to store.
     * @return the document ID of the persisted policy.
     * @throws IOException if storage fails.
     */
    @SuppressWarnings("unchecked")
    private String updatePolicy(SpaceService spaceService, Policy policy)
            throws IOException, IllegalStateException {
        // Get policy in the draft space
        Map<String, Object> currentPolicy = spaceService.getPolicy(Space.DRAFT.toString());

        // Safekeep unmodifiable values
        Map<String, Object> currentPolicyDoc =
                (Map<String, Object>) currentPolicy.get(Constants.KEY_DOCUMENT);
        if (currentPolicyDoc == null) {
            throw new IllegalStateException(
                    Constants.E_500_INTERNAL_SERVER_ERROR + " Policy document not found in draft space.");
        }

        // Validate integrations: allow reordering but prevent addition/removal
        List<String> currentIntegrations =
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyList());
        List<String> newIntegrations = policy.getIntegrations();

        // Validation for integrations array: allow reordering but prevent addition/removal
        RestResponse validationError =
                this.payloadValidations.validateListEquality(
                        currentIntegrations, newIntegrations, Constants.KEY_INTEGRATIONS);
        if (validationError != null) {
            throw new IllegalArgumentException(validationError.getMessage());
        }

        // Validation for filters array: allow reordering but prevent addition/removal
        List<String> currentFilters =
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_FILTERS, Collections.emptyList());
        List<String> newFilters = policy.getFilters();

        RestResponse filtersValidationError =
                this.payloadValidations.validateListEquality(
                        currentFilters, newFilters, Constants.KEY_FILTERS);
        if (filtersValidationError != null) {
            throw new IllegalArgumentException(filtersValidationError.getMessage());
        }

        String docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();
        @SuppressWarnings("unchecked")
        Map<String, Object> existingMeta =
                (Map<String, Object>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_METADATA, Collections.emptyMap());

        Object dateObj = existingMeta.get(Constants.KEY_DATE);
        if (dateObj == null) dateObj = currentPolicyDoc.get(Constants.KEY_DATE);
        String docCreationDate = dateObj != null ? dateObj.toString() : "";
        String docModificationDate = Instant.now().toString();

        // Update (set or overwrite unmodifiable values in incoming policy document)
        policy.setId(docId);
        policy.setDate(docCreationDate);
        policy.setModified(docModificationDate);

        Object compatObj = existingMeta.get(Constants.KEY_COMPATIBILITY);
        if (compatObj == null) {
            compatObj = currentPolicyDoc.get(Constants.KEY_COMPATIBILITY);
        }
        @SuppressWarnings("unchecked")
        List<String> existingCompatibility =
                (List<String>) (compatObj != null ? compatObj : Collections.emptyList());
        policy.getMetadata().setCompatibility(existingCompatibility);

        // Convert Policy to JsonNode.
        // nestMetadataFields removes root-level duplicate fields (title, author, date, etc.)
        // that Jackson emits from the public delegate getters in Policy, keeping them only
        // inside the nested "metadata" object — consistent with how initializeSpace() works.
        ObjectNode policyNode = mapper.valueToTree(policy);
        Resource.nestMetadataFields(policyNode);

        ContentIndex index = new ContentIndex(this.client, Constants.INDEX_POLICIES, null);
        try {
            // Build CTI wrapper with automatic hash calculation
            ObjectNode document = mapper.createObjectNode();
            document.set(Constants.KEY_DOCUMENT, policyNode);
            ObjectNode spaceNode = mapper.createObjectNode();
            spaceNode.put(Constants.KEY_NAME, Space.DRAFT.toString());
            document.set(Constants.KEY_SPACE, spaceNode);
            String hash = Resource.computeSha256(policyNode.toString());
            ObjectNode hashNode = mapper.createObjectNode();
            hashNode.put(Constants.KEY_SHA256, hash);
            document.set(Constants.KEY_HASH, hashNode);
            String draftPolicyId =
                    spaceService.findDocumentId(Constants.INDEX_POLICIES, Space.DRAFT.toString(), docId);
            IndexResponse indexResponse = index.create(draftPolicyId, document);
            return indexResponse.getId();
        } catch (Exception e) {
            throw new IllegalStateException("Draft policy not found: " + e.getMessage());
        }
    }
}
