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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.TermQueryBuilder;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.List;

import com.wazuh.contentmanager.action.CreateIntegrationAction;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

/** Transport action for creating Integration resources. */
public class TransportCreateIntegrationAction extends AbstractTransportCreateAction {

    @Inject
    public TransportCreateIntegrationAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(CreateIntegrationAction.NAME, transportService, actionFilters, client, engine);
    }

    @Override
    protected boolean requiresIntegrationId() {
        return false;
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
    protected RestResponse validatePayload(
            Client client, JsonNode root, JsonNode resource, IntegrationService integrationService) {
        RestResponse fieldValidation =
                this.documentValidations.validateRequiredFields(resource, List.of(Constants.KEY_CATEGORY));
        if (fieldValidation != null) return fieldValidation;

        RestResponse metadataValidation =
                this.documentValidations.validateMetadataFields(
                        resource, List.of(Constants.KEY_TITLE, Constants.KEY_AUTHOR));
        if (metadataValidation != null) return metadataValidation;

        String title = resource.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText();

        RestResponse duplicateValidation =
                this.documentValidations.validateDuplicateTitle(
                        client,
                        Constants.INDEX_INTEGRATIONS,
                        Space.DRAFT.toString(),
                        title,
                        null,
                        Constants.KEY_INTEGRATION);
        if (duplicateValidation != null) return duplicateValidation;

        ((ObjectNode) resource).set(Constants.KEY_RULES, MAPPER.createArrayNode());
        ((ObjectNode) resource).set(Constants.KEY_DECODERS, MAPPER.createArrayNode());
        ((ObjectNode) resource).set(Constants.KEY_KVDBS, MAPPER.createArrayNode());

        return null;
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
            securityAnalyticsService.upsertIntegration(resource, Space.DRAFT, POST);
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

    @Override
    protected void rollbackExternalServices(
            String id, SecurityAnalyticsService securityAnalyticsService) {
        securityAnalyticsService.deleteIntegration(id, Space.DRAFT);
    }

    @Override
    protected void linkToParent(
            Client client, String id, JsonNode root, IntegrationService integrationService)
            throws IOException {
        ContentIndex policiesIndex = new ContentIndex(client, Constants.INDEX_POLICIES);
        TermQueryBuilder queryBuilder =
                new TermQueryBuilder(Constants.Q_SPACE_NAME, Space.DRAFT.toString());
        ObjectNode searchResult = policiesIndex.searchByQuery(queryBuilder);

        if (searchResult == null
                || !searchResult.has(Constants.Q_HITS)
                || searchResult.get(Constants.Q_HITS).isEmpty()) {
            throw new IllegalStateException(Constants.E_500_MISSING_DRAFT_POLICY);
        }

        ArrayNode hitsArray = (ArrayNode) searchResult.get(Constants.Q_HITS);
        JsonNode draftPolicyHit = hitsArray.get(0);
        String draftPolicyId = draftPolicyHit.get(Constants.KEY_ID).asText();
        JsonNode document = draftPolicyHit.get(Constants.KEY_DOCUMENT);

        ArrayNode integrations = (ArrayNode) document.get(Constants.KEY_INTEGRATIONS);
        if (integrations == null) integrations = MAPPER.createArrayNode();

        integrations.add(id);

        String hash = Resource.computeSha256(document.toString());
        ((ObjectNode) draftPolicyHit.at("/hash")).put(Constants.KEY_SHA256, hash);

        policiesIndex.create(draftPolicyId, draftPolicyHit);
    }
}
