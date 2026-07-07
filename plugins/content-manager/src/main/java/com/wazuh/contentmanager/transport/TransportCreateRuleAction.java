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

import org.opensearch.OpenSearchException;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.Map;

import com.wazuh.contentmanager.action.CreateRuleAction;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
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
    protected void validatePayload(
            Client client,
            JsonNode root,
            JsonNode resource,
            IntegrationService integrationService,
            ActionListener<RestResponse> listener) {
        RestResponse metadataValidation =
                this.documentValidations.validateMetadataFields(
                        resource, java.util.List.of(Constants.KEY_TITLE));
        if (metadataValidation != null) {
            listener.onResponse(metadataValidation);
            return;
        }

        String title = resource.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText();
        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();

        // Step 1: validateDuplicateTitle (async)
        this.documentValidations.validateDuplicateTitleAsync(
                client,
                Constants.INDEX_RULES,
                Space.DRAFT.toString(),
                title,
                null,
                Constants.KEY_RULE,
                ActionListener.wrap(
                        duplicateError -> {
                            if (duplicateError != null) {
                                listener.onResponse(duplicateError);
                                return;
                            }
                            // Step 2: validateDocumentInSpace (async)
                            this.documentValidations.validateDocumentInSpaceAsync(
                                    client,
                                    Constants.INDEX_INTEGRATIONS,
                                    integrationId,
                                    Constants.KEY_INTEGRATION,
                                    ActionListener.wrap(
                                            spaceError -> {
                                                if (spaceError != null) {
                                                    listener.onResponse(
                                                            new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus()));
                                                    return;
                                                }
                                                // Step 3: validate logsource.product (async)
                                                validateLogsourceProduct(client, integrationId, resource, listener);
                                            },
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    @SuppressWarnings("unchecked")
    private void validateLogsourceProduct(
            Client client,
            String integrationId,
            JsonNode resource,
            ActionListener<RestResponse> listener) {
        client.get(
                new GetRequest(Constants.INDEX_INTEGRATIONS, integrationId),
                ActionListener.wrap(
                        integrationResponse -> {
                            if (integrationResponse.isExists()) {
                                Map<String, Object> source = integrationResponse.getSourceAsMap();
                                if (source != null && source.containsKey(Constants.KEY_DOCUMENT)) {
                                    Map<String, Object> doc =
                                            (Map<String, Object>) source.get(Constants.KEY_DOCUMENT);
                                    if (doc != null && doc.containsKey(Constants.KEY_METADATA)) {
                                        Map<String, Object> metadata =
                                                (Map<String, Object>) doc.get(Constants.KEY_METADATA);
                                        String integrationTitle =
                                                metadata != null ? (String) metadata.get(Constants.KEY_TITLE) : null;

                                        String ruleProduct = null;
                                        if (resource.has(Constants.KEY_LOGSOURCE)
                                                && resource.get(Constants.KEY_LOGSOURCE).has(Constants.KEY_PRODUCT)) {
                                            ruleProduct =
                                                    resource.get(Constants.KEY_LOGSOURCE).get(Constants.KEY_PRODUCT).asText();
                                        }

                                        if (integrationTitle == null || !integrationTitle.equals(ruleProduct)) {
                                            listener.onResponse(
                                                    new RestResponse(
                                                            "Rule logsource.product ('"
                                                                    + ruleProduct
                                                                    + "') must match the"
                                                                    + " integration's"
                                                                    + " metadata.title ('"
                                                                    + integrationTitle
                                                                    + "').",
                                                            RestStatus.BAD_REQUEST.getStatus()));
                                            return;
                                        }
                                    }
                                }
                            }
                            listener.onResponse(null);
                        },
                        listener::onFailure));
    }

    @Override
    protected void syncExternalServices(
            String id,
            JsonNode resource,
            SecurityAnalyticsService securityAnalyticsService,
            ActionListener<RestResponse> listener) {
        securityAnalyticsService.upsertRuleAsync(
                resource,
                Space.DRAFT,
                Method.POST,
                ActionListener.wrap(
                        response -> listener.onResponse(null),
                        e -> {
                            String msg = e.getMessage() != null ? e.getMessage() : "Unknown error";
                            if (msg.contains("Wazuh Common Schema (WCS)")) {
                                listener.onResponse(
                                        new RestResponse(
                                                Constants.E_SECURITY_ANALYTICS_ERROR
                                                        + " "
                                                        + SecurityAnalyticsServiceImpl.extractErrorMessage(msg),
                                                RestStatus.BAD_REQUEST.getStatus()));
                                return;
                            }
                            OpenSearchSecurityException secEx = TransportActionHelper.extractSecurityException(e);
                            if (secEx != null) {
                                listener.onResponse(
                                        new RestResponse(secEx.getMessage(), secEx.status().getStatus()));
                                return;
                            }
                            OpenSearchException osEx = TransportActionHelper.extractOpenSearchException(e);
                            if (osEx != null) {
                                listener.onResponse(new RestResponse(
                                    Constants.E_SECURITY_ANALYTICS_ERROR + " " + osEx.getMessage(),
                                    osEx.status().getStatus()));
                            }
                            listener.onResponse(
                                    new RestResponse(
                                            Constants.E_SECURITY_ANALYTICS_ERROR + " " + msg,
                                            RestStatus.INTERNAL_SERVER_ERROR.getStatus()));
                        }));
    }

    @Override
    protected void linkToParent(
            Client client,
            String id,
            JsonNode root,
            IntegrationService integrationService,
            ActionListener<Void> listener) {
        String integrationId = root.get(Constants.KEY_INTEGRATION).asText();
        integrationService.linkResourceToIntegrationAsync(
                integrationId, id, Constants.KEY_RULES, listener);
    }
}
