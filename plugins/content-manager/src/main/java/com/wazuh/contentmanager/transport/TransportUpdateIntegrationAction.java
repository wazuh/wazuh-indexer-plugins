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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.action.UpdateIntegrationAction;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.PUT;

/** Transport action for updating Integration resources. */
public class TransportUpdateIntegrationAction extends AbstractTransportUpdateAction {

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
    protected RestResponse preserveMetadata(
            ContentIndex index, String id, ObjectNode resourceNode) {
        RestResponse response = super.preserveMetadata(index, id, resourceNode);
        if (response != null) return response;

        JsonNode existingDoc = index.getDocument(id);
        if (existingDoc != null && existingDoc.has(Constants.KEY_DOCUMENT)) {
            @SuppressWarnings("unchecked")
            Map<String, Object> existing =
                    MAPPER.convertValue(existingDoc.get(Constants.KEY_DOCUMENT), Map.class);

            RestResponse error;
            error = this.checkListEquality(existing, resourceNode, Constants.KEY_RULES);
            if (error != null) return error;

            error = this.checkListEquality(existing, resourceNode, Constants.KEY_DECODERS);
            if (error != null) return error;

            error = this.checkListEquality(existing, resourceNode, Constants.KEY_KVDBS);
            return error;
        }
        return null;
    }

    private RestResponse checkListEquality(
            Map<String, Object> existing, JsonNode resource, String key) {
        @SuppressWarnings("unchecked")
        List<String> oldList = (List<String>) existing.getOrDefault(key, Collections.emptyList());
        List<String> newList = this.documentValidations.extractStringList(resource, key);
        return this.documentValidations.validateListEquality(oldList, newList, key);
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        RestResponse fieldValidation =
                this.documentValidations.validateRequiredFields(
                        resource, List.of(Constants.KEY_CATEGORY, Constants.KEY_ENABLED));
        if (fieldValidation != null) return fieldValidation;

        RestResponse metadataValidation =
                this.documentValidations.validateMetadataFields(
                        resource, List.of(Constants.KEY_TITLE, Constants.KEY_AUTHOR));
        if (metadataValidation != null) return metadataValidation;

        String title = resource.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText();
        String id = resource.get(Constants.KEY_ID).asText();

        return this.documentValidations.validateDuplicateTitle(
                client,
                Constants.INDEX_INTEGRATIONS,
                Space.DRAFT.toString(),
                title,
                id,
                Constants.KEY_INTEGRATION);
    }

    @Override
    protected RestResponse syncExternalServices(
            String id, JsonNode resource, SecurityAnalyticsService securityAnalyticsService) {
        // 1. Validate using the Engine.
        ObjectNode enginePayload = MAPPER.createObjectNode();
        enginePayload.set(Constants.KEY_RESOURCE, resource);
        enginePayload.put(Constants.KEY_TYPE, Constants.KEY_INTEGRATION);

        RestResponse engineResponse = this.engine.validate(enginePayload);
        if (engineResponse.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    Constants.E_400_ENGINE_VALIDATION_FAILED + " " + engineResponse.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }

        // 2. Send to Security Analytics.
        try {
            securityAnalyticsService.upsertIntegration(resource, Space.DRAFT, PUT);
        } catch (Exception e) {
            OpenSearchSecurityException secEx = TransportActionHelper.extractSecurityException(e);
            if (secEx != null) {
                return new RestResponse(secEx.getMessage(), secEx.status().getStatus());
            }
            return new RestResponse(
                    Constants.E_SECURITY_ANALYTICS_ERROR + " " + e.getMessage(),
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }

        return null;
    }
}
