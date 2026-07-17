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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.action.UpdateIntegrationAction;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.MockSecurityAnalyticsService;

import static org.opensearch.rest.RestRequest.Method.PUT;

/**
 * Transport action for updating Integration resources.
 *
 * <p>Integrations can be updated in both the {@code draft} and {@code standard} spaces. The target
 * space is resolved from the stored document, so callers keep using {@code PUT /integrations/{id}}
 * without supplying a space. Behaviour depends on the resolved space and the integration's {@code
 * mode}:
 *
 * <ul>
 *   <li><b>protected</b> integrations (Wazuh core content) cannot be modified in any space.
 *   <li><b>user-managed</b> integrations in the {@code draft} space are fully editable.
 *   <li><b>user-managed</b> integrations in the {@code standard} space only allow toggling {@code
 *       enabled}; every other field is preserved from the stored document.
 * </ul>
 */
public class TransportUpdateIntegrationAction extends AbstractTransportUpdateActionSpaces {

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);

    @Inject
    public TransportUpdateIntegrationAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(UpdateIntegrationAction.NAME, transportService, actionFilters, client, engine);
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_INTEGRATIONS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_INTEGRATION;
    }

    @Override
    protected Set<Space> getAllowedSpaces() {
        return validSpaces;
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        String id = resource.get(Constants.KEY_ID).asText();

        ContentIndex index = new ContentIndex(client, Constants.INDEX_INTEGRATIONS, null);
        JsonNode existingDoc = index.getDocument(id);
        if (existingDoc == null || !existingDoc.has(Constants.KEY_DOCUMENT)) {
            return new RestResponse(Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
        }
        JsonNode existingDocument = existingDoc.get(Constants.KEY_DOCUMENT);

        // Protected integrations cannot be modified
        if (this.documentValidations.isProtected(existingDocument)) {
            return new RestResponse(
                    String.format(Locale.ROOT, Constants.E_400_PROTECTED_INTEGRATION, id),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // The space is resolved
        String storedSpace = existingDoc.path(Constants.KEY_SPACE).path(Constants.KEY_NAME).asText();
        ((ObjectNode) root).put(Constants.KEY_SPACE, storedSpace);
        Space resolvedSpace;
        try {
            resolvedSpace = Space.fromValue(storedSpace);
        } catch (IllegalArgumentException e) {
            return new RestResponse(
                    Constants.E_400_RESOURCE_SPACE_INVALID, RestStatus.BAD_REQUEST.getStatus());
        }

        // 'enabled' is the only field that can be changed for standard integrations
        RestResponse fieldValidation =
                this.documentValidations.validateRequiredFields(resource, List.of(Constants.KEY_ENABLED));
        if (fieldValidation != null) {
            return fieldValidation;
        }

        if (Space.STANDARD.equals(resolvedSpace)) {
            return null;
        }

        // Draft integrations are fully editable
        fieldValidation =
                this.documentValidations.validateRequiredFields(
                        resource, List.of(Constants.KEY_CATEGORY, Constants.KEY_ENABLED));
        if (fieldValidation != null) {
            return fieldValidation;
        }

        RestResponse metadataValidation =
                this.documentValidations.validateMetadataFields(
                        resource, List.of(Constants.KEY_TITLE, Constants.KEY_AUTHOR));
        if (metadataValidation != null) {
            return metadataValidation;
        }

        String title = resource.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText();
        return this.documentValidations.validateDuplicateTitle(
                client, Constants.INDEX_INTEGRATIONS, storedSpace, title, id, Constants.KEY_INTEGRATION);
    }

    @Override
    protected RestResponse preserveMetadata(
            ContentIndex index, String id, ObjectNode resourceNode, Space space) {
        RestResponse response = super.preserveMetadata(index, id, resourceNode, space);
        if (response != null) {
            return response;
        }

        JsonNode existingDoc = index.getDocument(id);
        if (existingDoc == null || !existingDoc.has(Constants.KEY_DOCUMENT)) {
            return null;
        }
        JsonNode existingDocument = existingDoc.get(Constants.KEY_DOCUMENT);

        // The mode is server-managed and cannot be changed through the API
        resourceNode.remove(Constants.KEY_MODE);
        if (existingDocument.has(Constants.KEY_MODE)) {
            resourceNode.set(Constants.KEY_MODE, existingDocument.get(Constants.KEY_MODE));
        }

        if (Space.STANDARD.equals(space)) {
            // Only 'enabled' is mutable in the standard space
            boolean enabled = resourceNode.path(Constants.KEY_ENABLED).asBoolean(true);
            String modified =
                    resourceNode.path(Constants.KEY_METADATA).path(Constants.KEY_MODIFIED).asText(null);

            ObjectNode restored = ((ObjectNode) existingDocument).deepCopy();
            resourceNode.removeAll();
            resourceNode.setAll(restored);
            resourceNode.put(Constants.KEY_ID, id);
            resourceNode.put(Constants.KEY_ENABLED, enabled);
            if (modified != null) {
                Resource.getOrCreateMetadataNode(resourceNode).put(Constants.KEY_MODIFIED, modified);
            }
            return null;
        }

        @SuppressWarnings("unchecked")
        Map<String, Object> existing = MAPPER.convertValue(existingDocument, Map.class);

        RestResponse error = this.checkListEquality(existing, resourceNode, Constants.KEY_RULES);
        if (error != null) {
            return error;
        }

        error = this.checkListEquality(existing, resourceNode, Constants.KEY_DECODERS);
        if (error != null) {
            return error;
        }

        return this.checkListEquality(existing, resourceNode, Constants.KEY_KVDBS);
    }

    private RestResponse checkListEquality(
            Map<String, Object> existing, JsonNode resource, String key) {
        @SuppressWarnings("unchecked")
        List<String> oldList = (List<String>) existing.getOrDefault(key, Collections.emptyList());
        List<String> newList = this.documentValidations.extractStringList(resource, key);
        return this.documentValidations.validateListEquality(oldList, newList, key);
    }

    @Override
    protected void syncExternalServices(
            String id, JsonNode resource, Space space, ActionListener<RestResponse> listener) {
        SecurityAnalyticsService securityAnalyticsService = this.resolveSecurityAnalyticsService();

        // Standard integrations: only 'enabled' is mutable, and toggling it keeps the related
        // detector in sync.
        if (Space.STANDARD.equals(space)) {
            this.syncDetectorEnabledState(id, resource, securityAnalyticsService, listener);
            return;
        }

        // 1. Validate using the Engine (synchronous, not a Client call).
        ObjectNode enginePayload = MAPPER.createObjectNode();
        enginePayload.set(Constants.KEY_RESOURCE, resource);
        enginePayload.put(Constants.KEY_TYPE, Constants.KEY_INTEGRATION);

        RestResponse engineResponse = this.engine.validate(enginePayload);
        if (engineResponse.getStatus() != RestStatus.OK.getStatus()) {
            listener.onResponse(
                    new RestResponse(
                            Constants.E_400_ENGINE_VALIDATION_FAILED + " " + engineResponse.getMessage(),
                            RestStatus.BAD_REQUEST.getStatus()));
            return;
        }

        // 2. Send to Security Analytics (async).
        securityAnalyticsService.upsertIntegration(
                resource,
                Space.DRAFT,
                PUT,
                ActionListener.wrap(
                        response -> listener.onResponse(null),
                        e -> {
                            OpenSearchSecurityException secEx = TransportActionHelper.extractSecurityException(e);
                            if (secEx != null) {
                                listener.onResponse(
                                        new RestResponse(secEx.getMessage(), secEx.status().getStatus()));
                                return;
                            }
                            listener.onResponse(
                                    new RestResponse(
                                            Constants.E_SECURITY_ANALYTICS_ERROR + " " + e.getMessage(),
                                            RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                        }));
    }

    /**
     * Mirrors the integration's {@code enabled} state onto its related Security Analytics detector.
     *
     * <p>The detector shares the integration's document id, so its enabled state is toggled directly
     * by id via {@link SecurityAnalyticsService#setDetectorEnabled(String, boolean, ActionListener)},
     * which flips the existing detector (preserving its inputs, triggers and monitors) and is a no-op
     * when no detector exists.
     *
     * @param id the integration/detector document id.
     * @param resource the (restored) integration document being updated.
     * @param securityAnalyticsService the SAP service used to toggle the detector.
     * @param listener notified with {@code null} on success, or a {@link RestResponse} error if the
     *     detector could not be synced.
     */
    private void syncDetectorEnabledState(
            String id,
            JsonNode resource,
            SecurityAnalyticsService securityAnalyticsService,
            ActionListener<RestResponse> listener) {
        boolean enabled = resource.path(Constants.KEY_ENABLED).asBoolean(true);
        securityAnalyticsService.setDetectorEnabled(
                id,
                enabled,
                ActionListener.wrap(
                        response -> listener.onResponse(null),
                        e -> {
                            OpenSearchSecurityException secEx = TransportActionHelper.extractSecurityException(e);
                            if (secEx != null) {
                                listener.onResponse(
                                        new RestResponse(secEx.getMessage(), secEx.status().getStatus()));
                                return;
                            }
                            listener.onResponse(
                                    new RestResponse(
                                            Constants.E_SECURITY_ANALYTICS_ERROR + " " + e.getMessage(),
                                            RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                        }));
    }

    private SecurityAnalyticsService resolveSecurityAnalyticsService() {
        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            return new MockSecurityAnalyticsService();
        }
        return new SecurityAnalyticsServiceImpl(this.client);
    }
}
