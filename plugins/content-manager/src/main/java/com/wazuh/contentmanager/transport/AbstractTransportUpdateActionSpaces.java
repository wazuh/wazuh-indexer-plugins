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
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.Strings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.action.ContentUpdateRequest;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.MockSecurityAnalyticsService;
import com.wazuh.contentmanager.utils.YamlUtils;

/**
 * Abstract transport action for updating content resources (Spaces variant).
 *
 * <p>Mirrors the business logic from {@code AbstractUpdateActionSpaces.executeRequest()}.
 */
public abstract class AbstractTransportUpdateActionSpaces
        extends HandledTransportAction<ContentUpdateRequest, ContentResponse> {

    private static final Logger log = LogManager.getLogger(AbstractTransportUpdateActionSpaces.class);
    protected static final ObjectMapper MAPPER = new ObjectMapper();
    protected final PayloadValidations documentValidations = new PayloadValidations();
    protected final Client client;
    protected final EngineService engine;

    protected AbstractTransportUpdateActionSpaces(
            String actionName,
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(actionName, transportService, actionFilters, ContentUpdateRequest::new);
        this.client = client;
        this.engine = engine;
    }

    @Override
    protected void doExecute(
            Task task, ContentUpdateRequest request, ActionListener<ContentResponse> listener) {
        SecurityAnalyticsService securityAnalyticsService;
        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            securityAnalyticsService = new MockSecurityAnalyticsService();
        } else {
            securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        }
        SpaceService spaceService = new SpaceService(client);

        TransportActionHelper.validateDraftPolicyExists(
                client,
                () -> {
                    try {
                        RestResponse result = executeUpdateWorkflow(request, client, spaceService);
                        listener.onResponse(
                                new ContentResponse(result.getMessage(), RestStatus.fromCode(result.getStatus())));
                    } catch (Exception e) {
                        listener.onResponse(
                                new ContentResponse(
                                        e.getMessage() != null ? e.getMessage() : "Unexpected error",
                                        RestStatus.INTERNAL_SERVER_ERROR));
                    }
                },
                policyError ->
                        listener.onResponse(
                                new ContentResponse(
                                        policyError.getMessage(), RestStatus.fromCode(policyError.getStatus()))));
    }

    private RestResponse executeUpdateWorkflow(
            ContentUpdateRequest request, Client client, SpaceService spaceService) {
        byte[] body = request.getBodyContent();
        if (body == null || body.length == 0) {
            log.warn(
                    Constants.W_LOG_OPERATION_FAILED,
                    "Update",
                    this.getResourceType(),
                    "Request body is missing");
            return new RestResponse(
                    Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
        }

        String id = request.getId();

        try {
            // Validate ID
            RestResponse validationError =
                    this.documentValidations.validateRequiredParam(id, Constants.KEY_ID);
            if (validationError != null) return validationError;

            validationError = this.documentValidations.validateIdFormat(id, Constants.KEY_ID);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Update",
                        this.getResourceType(),
                        id,
                        "Invalid ID format");
                return validationError;
            }

            ContentIndex index = new ContentIndex(client, this.getIndexName(), null);
            if (!index.exists(id)) {
                log.warn(Constants.W_LOG_RESOURCE_NOT_FOUND, this.getResourceType(), id);
                return new RestResponse(
                        Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
            }

            // Parse body
            String rawYaml = null;
            JsonNode rootNode;
            ObjectNode resourceNode;
            boolean isYaml = "yaml".equals(request.getContentType());

            if (isYaml && this.supportsYamlField()) {
                try {
                    String yamlBody = new String(body, java.nio.charset.StandardCharsets.UTF_8);
                    rootNode = YamlUtils.fromYaml(yamlBody);
                } catch (IOException e) {
                    log.warn(
                            Constants.W_LOG_OPERATION_FAILED_ID,
                            "Update",
                            this.getResourceType(),
                            id,
                            "Invalid YAML format");
                    return new RestResponse(
                            Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
                }

                validationError = this.documentValidations.validateResourcePayload(rootNode, false);
                if (validationError != null) {
                    log.warn(
                            Constants.W_LOG_OPERATION_FAILED_ID,
                            "Payload validation",
                            this.getResourceType(),
                            id,
                            validationError.getMessage());
                    return validationError;
                }
                resourceNode = (ObjectNode) rootNode.get(Constants.KEY_RESOURCE);
                rawYaml = YamlUtils.toYaml(resourceNode);
            } else {
                try {
                    rootNode = MAPPER.readTree(new ByteArrayInputStream(body));
                } catch (IOException e) {
                    log.warn(
                            Constants.W_LOG_OPERATION_FAILED_ID,
                            "Update",
                            this.getResourceType(),
                            id,
                            "Invalid JSON format");
                    return new RestResponse(
                            Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST.getStatus());
                }

                validationError = this.documentValidations.validateResourcePayload(rootNode, false);
                if (validationError != null) {
                    log.warn(
                            Constants.W_LOG_OPERATION_FAILED_ID,
                            "Payload validation",
                            this.getResourceType(),
                            id,
                            validationError.getMessage());
                    return validationError;
                }
                resourceNode = (ObjectNode) rootNode.get(Constants.KEY_RESOURCE);
            }
            resourceNode.put(Constants.KEY_ID, id);

            // Resource-specific validation & Space validation
            validationError = this.validatePayload(client, rootNode, resourceNode);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Validation",
                        this.getResourceType(),
                        id,
                        validationError.getMessage());
                return validationError;
            }

            String spaceName = rootNode.path(Constants.KEY_SPACE).asText();

            String spaceError =
                    this.validateDocumentInSpace(
                            client,
                            this.getIndexName(),
                            id,
                            this.getResourceType(),
                            this.getAllowedSpaces(),
                            spaceName);
            if (spaceError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID, "Update", this.getResourceType(), id, spaceError);
                return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());
            }

            // Update timestamps & preserve metadata
            String currentTimestamp = getCurrentDate();
            Resource.setLastModificationTime(resourceNode, currentTimestamp);
            Resource.nestMetadataFields(resourceNode);
            validationError = this.preserveMetadata(index, id, resourceNode);
            if (validationError != null) {
                log.warn(
                        Constants.W_LOG_OPERATION_FAILED_ID,
                        "Preserve metadata validation",
                        this.getResourceType(),
                        id,
                        validationError.getMessage());
                return validationError;
            }

            // External Sync
            validationError = this.syncExternalServices(id, resourceNode);
            if (validationError != null) {
                log.error(
                        Constants.E_LOG_FAILED_TO,
                        "sync updated",
                        this.getResourceType(),
                        id,
                        "with external services. Reason: " + validationError.getMessage());
                return validationError;
            }

            // Indexing
            ObjectNode ctiWrapper = new Resource().wrapResource(resourceNode, spaceName);

            if (this.supportsYamlField()) {
                if (rawYaml != null) {
                    ctiWrapper.put(Constants.KEY_YAML, rawYaml);
                } else {
                    ctiWrapper.put(Constants.KEY_YAML, YamlUtils.toYaml(resourceNode));
                }
            }

            index.create(id, ctiWrapper);

            // Update Space Hash
            spaceService.calculateAndUpdate(List.of(spaceName));

            log.info(Constants.I_LOG_SUCCESS, "Updated", this.getResourceType(), id);
            return new RestResponse(id, RestStatus.OK.getStatus());

        } catch (Exception e) {
            OpenSearchSecurityException secEx = TransportActionHelper.extractSecurityException(e);
            if (secEx != null) {
                return new RestResponse(secEx.getMessage(), secEx.status().getStatus());
            }
            log.error(Constants.E_LOG_UNEXPECTED, "updating", this.getResourceType(), id, e.getMessage());
            return new RestResponse(
                    "Internal Server Error. " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    protected RestResponse preserveMetadata(ContentIndex index, String id, ObjectNode resourceNode) {
        JsonNode existingDoc = index.getDocument(id);
        if (existingDoc == null || !existingDoc.has(Constants.KEY_DOCUMENT)) return null;

        JsonNode doc = existingDoc.get(Constants.KEY_DOCUMENT);

        String date = null;
        if (doc.has(Constants.KEY_METADATA)
                && doc.get(Constants.KEY_METADATA).has(Constants.KEY_DATE)) {
            date = doc.get(Constants.KEY_METADATA).get(Constants.KEY_DATE).asText();
        }

        if (date != null) {
            ObjectNode metadataNode = Resource.getOrCreateMetadataNode(resourceNode);
            metadataNode.put(Constants.KEY_DATE, date);
        }

        if (!resourceNode.has(Constants.KEY_ENABLED)) {
            if (doc.has(Constants.KEY_ENABLED)) {
                resourceNode.put(Constants.KEY_ENABLED, doc.get(Constants.KEY_ENABLED).asBoolean());
            } else {
                resourceNode.put(Constants.KEY_ENABLED, true);
            }
        }
        return null;
    }

    private String validateDocumentInSpace(
            Client client,
            String index,
            String docId,
            String docType,
            Set<Space> validSpaces,
            String spaceNameFromRequest) {
        GetResponse response = client.prepareGet(index, docId).get();
        docType = Strings.capitalize(docType);

        if (!response.isExists()) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_NOT_FOUND, docType, docId);
        }

        Map<String, Object> source = response.getSourceAsMap();
        if (source == null || !source.containsKey(Constants.KEY_SPACE)) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_NOT_FOUND, docType, docId);
        }

        Object spaceObj = source.get(Constants.KEY_SPACE);
        if (!(spaceObj instanceof Map)) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_NOT_FOUND, docType, docId);
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> spaceMap = (Map<String, Object>) spaceObj;
        Object spaceName = spaceMap.get(Constants.KEY_NAME);

        if (this.getAllowedSpaces() != null
                && spaceNameFromRequest != null
                && !this.getAllowedSpaces().contains(Space.fromValue(spaceNameFromRequest))) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_SPACE_MISMATCH, validSpaces);
        }

        if (spaceNameFromRequest != null
                && !spaceNameFromRequest.equalsIgnoreCase(String.valueOf(spaceName))) {
            return String.format(Locale.ROOT, Constants.E_400_RESOURCE_SPACE_INVALID);
        }

        return null;
    }

    protected String getCurrentDate() {
        return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
    }

    protected boolean supportsYamlField() {
        return false;
    }

    protected abstract String getIndexName();

    protected abstract String getResourceType();

    protected abstract Set<Space> getAllowedSpaces();

    protected abstract RestResponse validatePayload(Client client, JsonNode root, JsonNode resource);

    protected abstract RestResponse syncExternalServices(String id, JsonNode resource);
}
