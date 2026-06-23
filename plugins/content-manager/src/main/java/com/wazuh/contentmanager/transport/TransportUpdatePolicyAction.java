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
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.UpdatePolicyAction;
import com.wazuh.contentmanager.action.UpdatePolicyRequest;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Policy;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport action for PUT /policy/{space}. Validates and stores an updated policy in the specified
 * space, recalculates space hashes, and optionally reloads the standard space into the Engine.
 */
public class TransportUpdatePolicyAction
        extends HandledTransportAction<UpdatePolicyRequest, MessageStatusResponse> {

    private static final Logger log = LogManager.getLogger(TransportUpdatePolicyAction.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    private final SpaceService spaceService;
    private final EngineService engineService;
    private final Client client;
    private final PayloadValidations payloadValidations;

    @Inject
    public TransportUpdatePolicyAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SpaceService spaceService,
            EngineService engineService,
            Client client) {
        super(UpdatePolicyAction.NAME, transportService, actionFilters, UpdatePolicyRequest::new);
        this.spaceService = spaceService;
        this.engineService = engineService;
        this.client = client;
        this.payloadValidations = new PayloadValidations();
    }

    @Override
    protected void doExecute(
            Task task, UpdatePolicyRequest request, ActionListener<MessageStatusResponse> listener) {
        // Lockdown gate: when enabled, sensitive configuration cannot be modified by anyone.
        if (PluginSettings.getInstance().isSensitiveConfigLocked()) {
            listener.onResponse(
                    new MessageStatusResponse(Constants.E_403_SENSITIVE_CONFIG_LOCKED, RestStatus.FORBIDDEN));
            return;
        }

        // 1. Check request body exists
        String body = request.getBody();
        if (body == null || body.isBlank()) {
            listener.onResponse(
                    new MessageStatusResponse(Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
            return;
        }

        try {
            // Extract and validate space parameter
            String spaceName = request.getSpace();
            if (!Space.DRAFT.equals(spaceName) && !Space.STANDARD.equals(spaceName)) {
                listener.onResponse(
                        new MessageStatusResponse(
                                String.format(
                                        Locale.ROOT,
                                        Constants.E_400_RESOURCE_SPACE_MISMATCH,
                                        Space.DRAFT + ", " + Space.STANDARD),
                                RestStatus.BAD_REQUEST));
                return;
            }

            // 2. Validate request content
            JsonNode jsonContent;
            try {
                jsonContent = mapper.readTree(body);
            } catch (IOException e) {
                listener.onResponse(
                        new MessageStatusResponse(
                                Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
                return;
            }

            // Validate "resource"
            if (!jsonContent.has(Constants.KEY_RESOURCE)) {
                listener.onResponse(
                        new MessageStatusResponse(
                                String.format(Locale.ROOT, Constants.E_400_MISSING_FIELD, Constants.KEY_RESOURCE),
                                RestStatus.BAD_REQUEST));
                return;
            }
            JsonNode resource = jsonContent.get(Constants.KEY_RESOURCE);
            log.debug(Constants.D_LOG_OPERATION, "Updating", Constants.KEY_POLICY, resource);
            Policy policy;
            try {
                policy = mapper.readValue(resource.toString(), Policy.class);
            } catch (IOException e) {
                listener.onResponse(
                        new MessageStatusResponse(
                                Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
                return;
            }

            // Normalize empty root_decoder to null
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
                        new MessageStatusResponse(
                                String.format(
                                        Locale.ROOT, Constants.E_400_MISSING_FIELD, String.join(", ", missingFields)),
                                RestStatus.BAD_REQUEST));
                return;
            }

            Set<String> knownEnrichmentTypes = this.spaceService.getKnownEnrichmentTypes();

            // Validate enrichments
            RestResponse enrichmentsValidationError =
                    this.payloadValidations.validateEnrichments(
                            policy.getEnrichments(), knownEnrichmentTypes);
            if (enrichmentsValidationError != null) {
                listener.onResponse(
                        new MessageStatusResponse(
                                enrichmentsValidationError.getMessage(),
                                RestStatus.fromCode(enrichmentsValidationError.getStatus())));
                return;
            }

            // 3. Update policy based on target space
            String policyId;
            if (Space.STANDARD.equals(spaceName)) {
                policyId = this.updateStandardPolicy(policy);
            } else {
                policyId = this.updatePolicy(policy);
            }

            // Regenerate space hash
            Set<String> changedSpaces = this.spaceService.calculateAndUpdate(List.of(spaceName));

            // Load the standard space into the Engine only if its hash changed
            if (changedSpaces.contains(Space.STANDARD.toString())) {
                this.loadStandardSpaceIntoEngine();
            }

            listener.onResponse(new MessageStatusResponse(policyId, RestStatus.OK));
        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_400_INVALID_REQUEST_BODY + " " + e.getMessage(), RestStatus.BAD_REQUEST));
        } catch (Exception e) {
            log.error(
                    Constants.E_LOG_OPERATION_FAILED, "updating", Constants.KEY_POLICY, e.getMessage(), e);
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_500_INTERNAL_SERVER_ERROR + " " + e.getMessage(),
                            RestStatus.INTERNAL_SERVER_ERROR));
        }
    }

    @SuppressWarnings("unchecked")
    private String updateStandardPolicy(Policy incomingPolicy)
            throws IOException, IllegalStateException {
        Map<String, Object> currentPolicy = this.spaceService.getPolicy(Space.STANDARD.toString());
        Map<String, Object> currentPolicyDoc =
                (Map<String, Object>) currentPolicy.get(Constants.KEY_DOCUMENT);
        if (currentPolicyDoc == null) {
            throw new IllegalStateException(
                    Constants.E_500_INTERNAL_SERVER_ERROR + " Policy document not found in standard space.");
        }

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

        String docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();

        @SuppressWarnings("unchecked")
        Map<String, Object> existingMetadata =
                (Map<String, Object>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_METADATA, Collections.emptyMap());

        Object dateObj = existingMetadata.get(Constants.KEY_DATE);
        if (dateObj == null) dateObj = currentPolicyDoc.get(Constants.KEY_DATE);
        String docCreationDate = dateObj != null ? dateObj.toString() : "";

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

        mergedPolicy.setEnrichments(incomingPolicy.getEnrichments());
        mergedPolicy.setFilters(incomingPolicy.getFilters());
        mergedPolicy.setEnabled(incomingPolicy.getEnabled());
        mergedPolicy.setIndexUnclassifiedEvents(incomingPolicy.getIndexUnclassifiedEvents());
        mergedPolicy.setIndexDiscardedEvents(incomingPolicy.getIndexDiscardedEvents());

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
                    this.spaceService.findDocumentId(
                            Constants.INDEX_POLICIES, Space.STANDARD.toString(), docId);
            IndexResponse indexResponse = index.create(standardPolicyId, document);
            return indexResponse.getId();
        } catch (Exception e) {
            throw new IllegalStateException("Standard policy not found: " + e.getMessage());
        }
    }

    @SuppressWarnings("unchecked")
    private String updatePolicy(Policy policy) throws IOException, IllegalStateException {
        Map<String, Object> currentPolicy = this.spaceService.getPolicy(Space.DRAFT.toString());

        Map<String, Object> currentPolicyDoc =
                (Map<String, Object>) currentPolicy.get(Constants.KEY_DOCUMENT);
        if (currentPolicyDoc == null) {
            throw new IllegalStateException(
                    Constants.E_500_INTERNAL_SERVER_ERROR + " Policy document not found in draft space.");
        }

        List<String> currentIntegrations =
                (List<String>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyList());
        List<String> newIntegrations = policy.getIntegrations();

        RestResponse validationError =
                this.payloadValidations.validateListEquality(
                        currentIntegrations, newIntegrations, Constants.KEY_INTEGRATIONS);
        if (validationError != null) {
            throw new IllegalArgumentException(validationError.getMessage());
        }

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

        ObjectNode policyNode = mapper.valueToTree(policy);
        Resource.nestMetadataFields(policyNode);

        ContentIndex index = new ContentIndex(this.client, Constants.INDEX_POLICIES, null);
        try {
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
                    this.spaceService.findDocumentId(Constants.INDEX_POLICIES, Space.DRAFT.toString(), docId);
            IndexResponse indexResponse = index.create(draftPolicyId, document);
            return indexResponse.getId();
        } catch (Exception e) {
            throw new IllegalStateException("Draft policy not found: " + e.getMessage());
        }
    }

    private void loadStandardSpaceIntoEngine() {
        if (this.engineService == null) {
            log.warn(Constants.E_LOG_ENGINE_IS_NULL);
            return;
        }
        try {
            JsonNode payload = this.spaceService.buildEnginePayload(Space.STANDARD.toString());
            RestResponse response = this.engineService.promote(payload);
            if (response.getStatus() == RestStatus.OK.getStatus()) {
                log.info("Engine load for standard space completed successfully.");
            } else {
                log.warn(
                        "Engine load for standard space returned status [{}]: {}",
                        response.getStatus(),
                        response.getMessage());
            }
        } catch (Exception e) {
            log.error("Failed to load standard space into Engine: {}", e.getMessage());
        }
    }
}
