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

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.util.Map;

import com.wazuh.contentmanager.action.CreateRuleAction;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsException;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for creating Rule resources. */
public class TransportCreateRuleAction extends AbstractTransportCreateAction {

    @Inject
    public TransportCreateRuleAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(CreateRuleAction.NAME, transportService, actionFilters, client, engine);
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_RULES;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_RULE;
    }

    @Override
    protected RestResponse validatePayload(
            Client client, JsonNode root, JsonNode resource, IntegrationService integrationService) {
        RestResponse metadataValidation =
                this.documentValidations.validateMetadataFields(
                        resource, java.util.List.of(Constants.KEY_TITLE));
        if (metadataValidation != null) return metadataValidation;

        String title = resource.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText();
        RestResponse duplicateValidation =
                this.documentValidations.validateDuplicateTitle(
                        client, Constants.INDEX_RULES, Space.DRAFT.toString(), title, null, Constants.KEY_RULE);
        if (duplicateValidation != null) return duplicateValidation;

        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        String spaceError =
                this.documentValidations.validateDocumentInSpace(
                        client, Constants.INDEX_INTEGRATIONS, integrationId, Constants.KEY_INTEGRATION);
        if (spaceError != null) return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());

        // Validate that logsource.product matches the integration's metadata.title
        GetResponse integrationResponse =
                client.prepareGet(Constants.INDEX_INTEGRATIONS, integrationId).get();
        if (integrationResponse.isExists()) {
            Map<String, Object> source = integrationResponse.getSourceAsMap();
            if (source != null && source.containsKey(Constants.KEY_DOCUMENT)) {
                @SuppressWarnings("unchecked")
                Map<String, Object> doc = (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
                if (doc != null && doc.containsKey(Constants.KEY_METADATA)) {
                    @SuppressWarnings("unchecked")
                    Map<String, Object> metadata = (Map<String, Object>) doc.get(Constants.KEY_METADATA);
                    String integrationTitle =
                            metadata != null ? (String) metadata.get(Constants.KEY_TITLE) : null;

                    String ruleProduct = null;
                    if (resource.has(Constants.KEY_LOGSOURCE)
                            && resource.get(Constants.KEY_LOGSOURCE).has(Constants.KEY_PRODUCT)) {
                        ruleProduct = resource.get(Constants.KEY_LOGSOURCE).get(Constants.KEY_PRODUCT).asText();
                    }

                    if (integrationTitle == null || !integrationTitle.equals(ruleProduct)) {
                        return new RestResponse(
                                "Rule logsource.product ('"
                                        + ruleProduct
                                        + "') must match the integration's metadata.title ('"
                                        + integrationTitle
                                        + "').",
                                RestStatus.BAD_REQUEST.getStatus());
                    }
                }
            }
        }

        return null;
    }

    @Override
    protected RestResponse syncExternalServices(
            String id, JsonNode resource, SecurityAnalyticsService securityAnalyticsService) {
        try {
            securityAnalyticsService.upsertRule(resource, Space.DRAFT, Method.POST);
            return null;
        } catch (SecurityAnalyticsException e) {
            return new RestResponse(
                    Constants.E_SECURITY_ANALYTICS_ERROR + " " + e.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        } catch (Exception e) {
            OpenSearchSecurityException secEx = TransportActionHelper.extractSecurityException(e);
            if (secEx != null) {
                return new RestResponse(secEx.getMessage(), secEx.status().getStatus());
            }
            String msg = e.getMessage() != null ? e.getMessage() : "Unknown error";
            return new RestResponse(
                    Constants.E_SECURITY_ANALYTICS_ERROR + " " + msg,
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    @Override
    protected void linkToParent(
            Client client, String id, JsonNode root, IntegrationService integrationService)
            throws IOException {
        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        integrationService.linkResourceToIntegration(integrationId, id, Constants.KEY_RULES);
    }
}
