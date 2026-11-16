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
import java.util.TreeSet;

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
    private final Client client;
    private final PayloadValidations payloadValidations;
    private final UserOverridesService userOverridesService;

    @Inject
    public TransportUpdatePolicyAction(
            TransportService transportService,
            ActionFilters actionFilters,
            SpaceService spaceService,
            Client client,
            UserOverridesService userOverridesService) {
        super(UpdatePolicyAction.NAME, transportService, actionFilters, UpdatePolicyRequest::new);
        this.spaceService = spaceService;
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
                            currentPolicy ->
                                    afterGetPolicy(
                                            currentPolicy, policy, resource, spaceName, knownEnrichmentTypes, listener),
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
            JsonNode resource,
            String spaceName,
            Set<String> knownEnrichmentTypes,
            ActionListener<MessageStatusResponse> listener) {
        try {
            if (currentPolicy == null) {
                log.error(Constants.E_LOG_POLICY_DOCUMENT_MISSING, spaceName);
                listener.onResponse(
                        new MessageStatusResponse(
                                "Policy document not found in " + spaceName + " space.",
                                RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }

            Map<String, Object> currentPolicyDoc =
                    (Map<String, Object>) currentPolicy.get(Constants.KEY_DOCUMENT);
            if (currentPolicyDoc == null) {
                log.error(Constants.E_LOG_POLICY_DOCUMENT_MISSING, spaceName);
                listener.onResponse(
                        new MessageStatusResponse(
                                "Policy document not found in " + spaceName + " space.",
                                RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }

            // What the policy has before this save: CTI's list without what the user already turned off.
            final List<String> enrichmentsBefore =
                    new ArrayList<>(
                            (List<String>)
                                    currentPolicyDoc.getOrDefault(
                                            Constants.KEY_ENRICHMENTS, Collections.emptyList()));

            keepOmittedLists(resource, incomingPolicy, currentPolicyDoc);

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
            final SavedSettings pendingOverride =
                    Space.STANDARD.equals(spaceName)
                            ? new SavedSettings(
                                    incomingPolicy.getEnabled(),
                                    incomingPolicy.getIndexUnclassifiedEvents(),
                                    incomingPolicy.getIndexDiscardedEvents(),
                                    resource.hasNonNull(Constants.KEY_ENRICHMENTS)
                                            ? incomingPolicy.getEnrichments()
                                            : null,
                                    enrichmentsBefore,
                                    knownEnrichmentTypes)
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
            SavedSettings pendingOverride,
            ActionListener<MessageStatusResponse> listener) {
        if (documentId == null) {
            log.error(Constants.E_LOG_POLICY_DOCUMENT_MISSING, spaceName);
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
            SavedSettings pendingOverride,
            ActionListener<MessageStatusResponse> listener) {
        // Recalculate space hash (async)
        this.spaceService.calculateAndUpdate(
                List.of(spaceName),
                ActionListener.wrap(
                        changedSpaces -> {
                            TransportActionHelper.reloadStandardSpaceIntoEngine(changedSpaces, this.client);
                            this.recordPolicySettings(
                                    pendingOverride,
                                    () -> listener.onResponse(new MessageStatusResponse(policyId, RestStatus.OK)));
                        },
                        e -> respondWithError(listener, e)));
    }

    /**
     * Records the settings the user can change on the standard policy, so the next rebuild of that
     * space can put them back.
     *
     * <p>Runs after the policy has been indexed, never before: recording a change that failed to
     * apply would make the next sync apply it anyway, turning a rejected request into a delayed one.
     *
     * <p>The three flags are required, so they are recorded on every save: editing the standard
     * policy makes them the user's from then on. The enrichments are recorded only when the request
     * carries them; a request without the field decides nothing about it.
     *
     * <p>A registry failure is logged and swallowed. The policy is already written, so the user's
     * request succeeded; failing it here would be a lie.
     *
     * @param sent what this save decided, or {@code null} for a space other than {@code standard},
     *     which is the only one rebuilt from CTI and so the only one that can lose settings.
     * @param onDone run once recording has finished, successfully or not.
     */
    private void recordPolicySettings(SavedSettings sent, Runnable onDone) {
        if (sent == null) {
            onDone.run();
            return;
        }

        this.userOverridesService.update(
                Space.STANDARD.toString(),
                current -> mergeRecordedSettings(current, sent),
                ActionListener.wrap(
                        v -> onDone.run(),
                        e -> {
                            log.error(Constants.E_LOG_USER_OVERRIDES_REGISTRY_WRITE_FAILED, e.getMessage());
                            onDone.run();
                        }));
    }

    /**
     * Records this save's settings, replacing whatever the registry held for the policy.
     *
     * <p>The enrichments are recorded as the types the user turned off, while the request carries the
     * ones left on. Those turned off are the types CTI publishes that the request leaves out. The
     * stored policy alone does not hold every type CTI publishes, because it already lacks the ones
     * turned off in earlier saves, so those are added back as candidates: a type turned off stays off
     * until a request sends it again, also while CTI does not publish it.
     *
     * <p>When the request left the enrichments out, the choice already recorded stays as it is, and
     * if there was none the field stays {@code null} so CTI keeps deciding it.
     *
     * <p>The stored filters and integration decisions pass through untouched: all three sections
     * share one registry document, so returning anything else here would delete them.
     */
    private static UserOverrides mergeRecordedSettings(UserOverrides current, SavedSettings sent) {
        UserOverrides.PolicySettings prior = current.getPolicy();
        UserOverrides.PolicySettings recorded;
        if (sent.enrichments() == null) {
            recorded =
                    prior != null && prior.isLegacy()
                            ? UserOverrides.PolicySettings.legacy(
                                    sent.enabled(),
                                    sent.indexUnclassifiedEvents(),
                                    sent.indexDiscardedEvents(),
                                    prior.getLegacyEnrichments())
                            : new UserOverrides.PolicySettings(
                                    sent.enabled(),
                                    sent.indexUnclassifiedEvents(),
                                    sent.indexDiscardedEvents(),
                                    prior != null ? prior.getDisabledEnrichments() : null);
        } else {
            Set<String> disabled = new LinkedHashSet<>(sent.enrichmentsBefore());
            if (prior != null) {
                // A legacy override holds the list kept, so what it turned off is resolved against
                // every type known from the IOC catalog: the stored policy already lacks those types.
                Set<String> legacyCandidates = new LinkedHashSet<>(sent.enrichmentsBefore());
                legacyCandidates.addAll(new TreeSet<>(sent.knownEnrichmentTypes()));
                List<String> priorDisabled = prior.resolveDisabledEnrichments(legacyCandidates);
                if (priorDisabled != null) {
                    disabled.addAll(priorDisabled);
                }
            }
            disabled.removeAll(sent.enrichments());
            recorded =
                    new UserOverrides.PolicySettings(
                            sent.enabled(),
                            sent.indexUnclassifiedEvents(),
                            sent.indexDiscardedEvents(),
                            new ArrayList<>(disabled));
        }
        return new UserOverrides(recorded, current.getFilters(), current.getIntegrations());
    }

    /**
     * What a save of the standard policy decided, and what is needed to record it as a delta.
     *
     * @param enabled the {@code enabled} flag sent.
     * @param indexUnclassifiedEvents the {@code index_unclassified_events} flag sent.
     * @param indexDiscardedEvents the {@code index_discarded_events} flag sent.
     * @param enrichments the enrichments sent, or {@code null} when the request left them out.
     * @param enrichmentsBefore the enrichments the stored policy had before this save.
     * @param knownEnrichmentTypes the enrichment types known from the IOC catalog.
     */
    private record SavedSettings(
            Boolean enabled,
            Boolean indexUnclassifiedEvents,
            Boolean indexDiscardedEvents,
            List<String> enrichments,
            List<String> enrichmentsBefore,
            Set<String> knownEnrichmentTypes) {}

    /**
     * Gives the incoming policy the stored value of every list the request left out.
     *
     * <p>{@link Policy} turns an absent list into an empty one, which the rest of the update would
     * read as "remove everything". Only the raw request can tell the two apart, so the lists the
     * client did not send are taken from the stored policy here, before they are validated and
     * merged. A JSON {@code null} counts as absent.
     */
    @SuppressWarnings("unchecked")
    private static void keepOmittedLists(
            JsonNode resource, Policy incomingPolicy, Map<String, Object> currentPolicyDoc) {
        if (!resource.hasNonNull(Constants.KEY_INTEGRATIONS)) {
            incomingPolicy.setIntegrations(
                    (List<String>) currentPolicyDoc.get(Constants.KEY_INTEGRATIONS));
        }
        if (!resource.hasNonNull(Constants.KEY_FILTERS)) {
            incomingPolicy.setFilters((List<String>) currentPolicyDoc.get(Constants.KEY_FILTERS));
        }
        if (!resource.hasNonNull(Constants.KEY_ENRICHMENTS)) {
            incomingPolicy.setEnrichments((List<String>) currentPolicyDoc.get(Constants.KEY_ENRICHMENTS));
        }
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

    private void respondWithError(ActionListener<MessageStatusResponse> listener, Exception e) {
        RestResponse classified = TransportActionHelper.classifyException(e);
        if (classified != null) {
            RestStatus status = RestStatus.fromCode(classified.getStatus());
            log.warn(Constants.W_LOG_VALIDATION_FAILED, classified.getMessage());
            listener.onResponse(new MessageStatusResponse(classified.getMessage(), status));
            return;
        }
        log.error(
                Constants.E_LOG_OPERATION_FAILED, "updating", Constants.KEY_POLICY, e.getMessage(), e);
        listener.onResponse(
                new MessageStatusResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
    }
}
