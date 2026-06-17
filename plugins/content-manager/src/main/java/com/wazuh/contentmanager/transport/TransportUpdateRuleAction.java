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
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest.Method;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.List;

import com.wazuh.contentmanager.action.UpdateRuleAction;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsException;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for updating Rule resources. */
public class TransportUpdateRuleAction extends AbstractTransportUpdateAction {

    @Inject
    public TransportUpdateRuleAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(UpdateRuleAction.NAME, transportService, actionFilters, client, engine);
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
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        RestResponse fieldValidation =
                this.documentValidations.validateRequiredFields(
                        resource, List.of(Constants.KEY_ENABLED));
        if (fieldValidation != null) return fieldValidation;

        RestResponse metadataValidation =
                this.documentValidations.validateMetadataFields(
                        resource, List.of(Constants.KEY_TITLE, Constants.KEY_AUTHOR));
        if (metadataValidation != null) return metadataValidation;

        String title = resource.get(Constants.KEY_METADATA).get(Constants.KEY_TITLE).asText();
        String id = resource.get(Constants.KEY_ID).asText();

        return this.documentValidations.validateDuplicateTitle(
                client,
                Constants.INDEX_RULES,
                Space.DRAFT.toString(),
                title,
                id,
                Constants.KEY_RULE);
    }

    @Override
    protected RestResponse syncExternalServices(
            String id, JsonNode resource, SecurityAnalyticsService securityAnalyticsService) {
        try {
            securityAnalyticsService.upsertRule(resource, Space.DRAFT, Method.PUT);
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
}
