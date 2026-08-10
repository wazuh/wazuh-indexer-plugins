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
import org.opensearch.OpenSearchException;
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
import java.util.LinkedHashSet;
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
import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
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
    private final UserOverridesService userOverridesService;

    @Inject
    public TransportUpdatePolicyAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SpaceService spaceService,
            EngineService engineService,
            Client client,
            UserOverridesService userOverridesService) {
        super(UpdatePolicyAction.NAME, transportService, actionFilters, UpdatePolicyRequest::new);
        this.spaceService = spaceService;
        this.engineService = engineService;
        this.client = client;
        this.payloadValidations = new PayloadValidations();
        this.userOverridesService = userOverridesService;
    }

    @Override
    protected void doExecute(
            Task task, UpdatePolicyRequest request, ActionListener<MessageStatusResponse> listener) {
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

            // 3. Fetch current policy and apply update (async)
            this.spaceService.getPolicy(
                    spaceName,
                    ActionListener.wrap(
                            currentPolicy -> afterGetPolicy(currentPolicy, policy, spaceName, listener),
                            e -> respondWithError(listener, e)));

        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_400_INVALID_REQUEST_BODY + " " + e.getMessage(), RestStatus.BAD_REQUEST));
        } catch (Exception e) {
            respondWithError(listener, e);
        }
    }

    @SuppressWarnings("unchecked")
    private void afterGetPolicy(
            Map<String, Object> currentPolicy,
            Policy incomingPolicy,
            String spaceName,
            ActionListener<MessageStatusResponse> listener) {
        try {
            if (currentPolicy == null) {
                listener.onResponse(
                        new MessageStatusResponse(
                                "Policy document not found in " + spaceName + " space.",
                                RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }

            Map<String, Object> currentPolicyDoc =
                    (Map<String, Object>) currentPolicy.get(Constants.KEY_DOCUMENT);
            if (currentPolicyDoc == null) {
                listener.onResponse(
                        new MessageStatusResponse(
                                "Policy document not found in " + spaceName + " space.",
                                RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }

            // Validate immutable lists
            if (Space.STANDARD.equals(spaceName)) {
                List<String> currentFilters =
                        (List<String>)
                                currentPolicyDoc.getOrDefault(Constants.KEY_FILTERS, Collections.emptyList());
                RestResponse filtersValidationError =
                        this.payloadValidations.validateListEquality(
                                currentFilters, incomingPolicy.getFilters(), Constants.KEY_FILTERS);
                if (filtersValidationError != null) {
                    listener.onResponse(
                            new MessageStatusResponse(
                                    filtersValidationError.getMessage(), RestStatus.BAD_REQUEST));
                    return;
                }
            } else {
                List<String> currentIntegrations =
                        (List<String>)
                                currentPolicyDoc.getOrDefault(Constants.KEY_INTEGRATIONS, Collections.emptyList());
                RestResponse validationError =
                        this.payloadValidations.validateListEquality(
                                currentIntegrations, incomingPolicy.getIntegrations(), Constants.KEY_INTEGRATIONS);
                if (validationError != null) {
                    listener.onResponse(
                            new MessageStatusResponse(validationError.getMessage(), RestStatus.BAD_REQUEST));
                    return;
                }

                List<String> currentFilters =
                        (List<String>)
                                currentPolicyDoc.getOrDefault(Constants.KEY_FILTERS, Collections.emptyList());
                RestResponse filtersValidationError =
                        this.payloadValidations.validateListEquality(
                                currentFilters, incomingPolicy.getFilters(), Constants.KEY_FILTERS);
                if (filtersValidationError != null) {
                    listener.onResponse(
                            new MessageStatusResponse(
                                    filtersValidationError.getMessage(), RestStatus.BAD_REQUEST));
                    return;
                }
            }

            // Merge policy
            ObjectNode policyNode;
            String docId;
            if (Space.STANDARD.equals(spaceName)) {
                policyNode = mergeStandardPolicy(incomingPolicy, currentPolicyDoc);
                docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();
            } else {
                policyNode = mergeDraftPolicy(incomingPolicy, currentPolicyDoc);
                docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();
            }

            // Build index document
            ObjectNode document = mapper.createObjectNode();
            document.set(Constants.KEY_DOCUMENT, policyNode);
            ObjectNode spaceNode = mapper.createObjectNode();
            spaceNode.put(Constants.KEY_NAME, spaceName);
            document.set(Constants.KEY_SPACE, spaceNode);
            String hash = Resource.computeSha256(policyNode.toString());
            ObjectNode hashNode = mapper.createObjectNode();
            hashNode.put(Constants.KEY_SHA256, hash);
            document.set(Constants.KEY_HASH, hashNode);

            // Only the standard space is rebuilt from CTI, so only its settings need recording.
            final PendingOverride pendingOverride =
                    Space.STANDARD.equals(spaceName)
                            ? new PendingOverride(
                                    incomingPolicy,
                                    (List<String>)
                                            currentPolicyDoc.getOrDefault(
                                                    Constants.KEY_ENRICHMENTS, Collections.emptyList()))
                            : null;

            // Find the real document _id (async)
            this.spaceService.findDocumentIdAsync(
                    Constants.INDEX_POLICIES,
                    spaceName,
                    docId,
                    ActionListener.wrap(
                            realId -> afterFindDocumentId(realId, document, spaceName, pendingOverride, listener),
                            e -> respondWithError(listener, e)));

        } catch (IllegalArgumentException e) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, e.getMessage());
            listener.onResponse(
                    new MessageStatusResponse(
                            Constants.E_400_INVALID_REQUEST_BODY + " " + e.getMessage(), RestStatus.BAD_REQUEST));
        } catch (Exception e) {
            respondWithError(listener, e);
        }
    }

    private void afterFindDocumentId(
            String documentId,
            ObjectNode document,
            String spaceName,
            PendingOverride pendingOverride,
            ActionListener<MessageStatusResponse> listener) {
        if (documentId == null) {
            listener.onResponse(
                    new MessageStatusResponse(
                            "Policy document not found in " + spaceName + " space.",
                            RestStatus.INTERNAL_SERVER_ERROR));
            return;
        }

        // Index the document (async)
        ContentIndex index = new ContentIndex(this.client, Constants.INDEX_POLICIES, null);
        index.create(
                documentId,
                document,
                ActionListener.wrap(
                        indexResponse ->
                                afterIndex(indexResponse.getId(), spaceName, pendingOverride, listener),
                        e -> respondWithError(listener, e)));
    }

    private void afterIndex(
            String policyId,
            String spaceName,
            PendingOverride pendingOverride,
            ActionListener<MessageStatusResponse> listener) {
        // Recalculate space hash (async)
        this.spaceService.calculateAndUpdate(
                List.of(spaceName),
                ActionListener.wrap(
                        changedSpaces -> {
                            if (changedSpaces.contains(Space.STANDARD.toString())) {
                                this.loadStandardSpaceIntoEngine();
                            }
                            this.recordPolicySettings(
                                    pendingOverride,
                                    () -> listener.onResponse(new MessageStatusResponse(policyId, RestStatus.OK)));
                        },
                        e -> respondWithError(listener, e)));
    }

    /**
     * What the user-overrides registry needs to record once the policy write has been committed.
     *
     * <p>{@code null} for every space other than {@code standard}, which is the only one rebuilt from
     * CTI and therefore the only one whose settings can be lost.
     *
     * @param incomingPolicy the policy the client sent.
     * @param currentEnrichments the enrichments stored before this update, needed to work out what
     *     the user just changed.
     */
    private record PendingOverride(Policy incomingPolicy, List<String> currentEnrichments) {}

    /**
     * Records the settings the user can change on the standard policy, so the next rebuild of that
     * space can put them back.
     *
     * <p>Runs after the policy has been indexed, never before: recording a change that failed to
     * apply would make the next sync apply it anyway, turning a rejected request into a delayed one.
     *
     * <p>All four settings are recorded on every save, by design — editing the standard policy makes
     * its settings the user's from then on. Enrichments are the exception: they are stored as a delta
     * against the list CTI publishes, so an enrichment CTI adds later still reaches a user who
     * customised the selection.
     *
     * <p>A registry failure is logged and swallowed. The policy is already written, so the user's
     * request succeeded; failing it here would be a lie.
     *
     * @param pending what to record, or {@code null} when there is nothing to record.
     * @param onDone run once recording has finished, successfully or not.
     */
    private void recordPolicySettings(PendingOverride pending, Runnable onDone) {
        if (pending == null) {
            onDone.run();
            return;
        }

        List<String> incomingEnrichments = pending.incomingPolicy().getEnrichments();
        Set<String> incoming =
                new LinkedHashSet<>(
                        incomingEnrichments != null ? incomingEnrichments : Collections.emptyList());
        Set<String> effective = new LinkedHashSet<>(pending.currentEnrichments());

        Set<String> removedNow = new LinkedHashSet<>(effective);
        removedNow.removeAll(incoming);
        Set<String> addedNow = new LinkedHashSet<>(incoming);
        addedNow.removeAll(effective);

        this.userOverridesService.update(
                Space.STANDARD.toString(),
                current -> mergeRecordedSettings(current, pending.incomingPolicy(), removedNow, addedNow),
                ActionListener.wrap(
                        v -> onDone.run(),
                        e -> {
                            log.error(Constants.E_LOG_USER_OVERRIDES_REGISTRY_WRITE_FAILED, e.getMessage());
                            onDone.run();
                        }));
    }

    /**
     * Folds this save's enrichment change into whatever the registry already holds.
     *
     * <p>Removing something the user had added, or adding back something they had removed, cancels
     * the earlier entry rather than accumulating both — otherwise a value could sit in both sets at
     * once and the delta would stop describing the user's intent.
     *
     * <p>The stored filters pass through untouched: the policy and the filters share one registry
     * document, so returning anything else here would delete the user's filters.
     */
    private static UserOverrides mergeRecordedSettings(
            UserOverrides current, Policy incomingPolicy, Set<String> removedNow, Set<String> addedNow) {
        Set<String> removed = new LinkedHashSet<>();
        Set<String> added = new LinkedHashSet<>();
        if (current.getPolicy() != null && current.getPolicy().getEnrichments() != null) {
            removed.addAll(current.getPolicy().getEnrichments().getRemoved());
            added.addAll(current.getPolicy().getEnrichments().getAdded());
        }
        removed.addAll(removedNow);
        removed.removeAll(addedNow);
        added.addAll(addedNow);
        added.removeAll(removedNow);

        return new UserOverrides(
                new UserOverrides.PolicySettings(
                        incomingPolicy.getEnabled(),
                        incomingPolicy.getIndexUnclassifiedEvents(),
                        incomingPolicy.getIndexDiscardedEvents(),
                        new UserOverrides.EnrichmentDelta(removed, added)),
                current.getFilters());
    }

    @SuppressWarnings("unchecked")
    private ObjectNode mergeStandardPolicy(
            Policy incomingPolicy, Map<String, Object> currentPolicyDoc) {
        String docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();

        Map<String, Object> existingMetadata =
                (Map<String, Object>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_METADATA, Collections.emptyMap());

        Object dateObj = existingMetadata.get(Constants.KEY_DATE);
        if (dateObj == null) dateObj = currentPolicyDoc.get(Constants.KEY_DATE);
        String docCreationDate = dateObj != null ? dateObj.toString() : "";

        String incomingModified = incomingPolicy.getModified();
        Policy mergedPolicy = new Policy();
        mergedPolicy.setId(docId);
        mergedPolicy.setDate(docCreationDate);
        mergedPolicy.setModified(
                incomingModified != null && !incomingModified.isBlank()
                        ? incomingModified
                        : Instant.now().toString());

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
        List<String> existingReferences =
                (List<String>) (refObj != null ? refObj : Collections.emptyList());
        mergedPolicy.setReferences(existingReferences);

        Object compatObj = existingMetadata.get(Constants.KEY_COMPATIBILITY);
        if (compatObj == null) {
            compatObj = currentPolicyDoc.get(Constants.KEY_COMPATIBILITY);
        }
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
        return policyNode;
    }

    @SuppressWarnings("unchecked")
    private ObjectNode mergeDraftPolicy(Policy incomingPolicy, Map<String, Object> currentPolicyDoc) {
        String docId = currentPolicyDoc.getOrDefault(Constants.KEY_ID, "").toString();

        Map<String, Object> existingMeta =
                (Map<String, Object>)
                        currentPolicyDoc.getOrDefault(Constants.KEY_METADATA, Collections.emptyMap());

        Object dateObj = existingMeta.get(Constants.KEY_DATE);
        if (dateObj == null) dateObj = currentPolicyDoc.get(Constants.KEY_DATE);
        String docCreationDate = dateObj != null ? dateObj.toString() : "";
        String incomingModified = incomingPolicy.getModified();
        String docModificationDate =
                incomingModified != null && !incomingModified.isBlank()
                        ? incomingModified
                        : Instant.now().toString();

        incomingPolicy.setId(docId);
        incomingPolicy.setDate(docCreationDate);
        incomingPolicy.setModified(docModificationDate);

        Object compatObj = existingMeta.get(Constants.KEY_COMPATIBILITY);
        if (compatObj == null) {
            compatObj = currentPolicyDoc.get(Constants.KEY_COMPATIBILITY);
        }
        List<String> existingCompatibility =
                (List<String>) (compatObj != null ? compatObj : Collections.emptyList());
        incomingPolicy.getMetadata().setCompatibility(existingCompatibility);

        ObjectNode policyNode = mapper.valueToTree(incomingPolicy);
        Resource.nestMetadataFields(policyNode);
        return policyNode;
    }

    private void loadStandardSpaceIntoEngine() {
        if (this.engineService == null) {
            log.warn(Constants.E_LOG_ENGINE_IS_NULL);
            return;
        }
        this.spaceService.buildEnginePayload(
                Space.STANDARD.toString(),
                ActionListener.wrap(
                        payload -> {
                            try {
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
                        },
                        e -> log.error("Failed to load standard space into Engine: {}", e.getMessage())));
    }

    private void respondWithError(ActionListener<MessageStatusResponse> listener, Exception e) {
        OpenSearchException osEx = TransportActionHelper.extractOpenSearchException(e);
        if (osEx != null && osEx.status().getStatus() < 500) {
            log.warn(Constants.W_LOG_VALIDATION_FAILED, osEx.getMessage());
            listener.onResponse(new MessageStatusResponse(osEx.getMessage(), osEx.status()));
            return;
        }
        log.error(
                Constants.E_LOG_OPERATION_FAILED, "updating", Constants.KEY_POLICY, e.getMessage(), e);
        listener.onResponse(
                new MessageStatusResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR + " " + e.getMessage(),
                        RestStatus.INTERNAL_SERVER_ERROR));
    }
}
