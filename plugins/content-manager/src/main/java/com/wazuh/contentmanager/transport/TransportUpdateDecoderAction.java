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

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import com.wazuh.contentmanager.action.UpdateDecoderAction;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for updating Decoder resources. */
public class TransportUpdateDecoderAction extends AbstractTransportUpdateAction {

    @Inject
    public TransportUpdateDecoderAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(UpdateDecoderAction.NAME, transportService, actionFilters, client, engine);
    }

    @Override
    protected boolean supportsYamlField() {
        return true;
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_DECODERS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_DECODER;
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        return null;
    }

    @Override
    protected RestResponse syncExternalServices(
            String id, JsonNode resource, SecurityAnalyticsService securityAnalyticsService) {
        RestResponse engineValidation = this.engine.validateResource(Constants.KEY_DECODER, resource);
        if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    Constants.E_400_ENGINE_VALIDATION_FAILED + " " + engineValidation.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }
}
