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

import java.util.List;
import java.util.Set;

import com.wazuh.contentmanager.action.UpdateFilterAction;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for updating Filter resources (Spaces variant). */
public class TransportUpdateFilterAction extends AbstractTransportUpdateActionSpaces {

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);

    @Inject
    public TransportUpdateFilterAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(UpdateFilterAction.NAME, transportService, actionFilters, client, engine);
    }

    @Override
    protected boolean supportsYamlField() {
        return true;
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_FILTERS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_FILTER;
    }

    @Override
    public Set<Space> getAllowedSpaces() {
        return validSpaces;
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        String spaceName = root.path(Constants.KEY_SPACE).asText(null);
        if (!isValidSpace(spaceName)) {
            return new RestResponse(
                    Constants.E_400_RESOURCE_SPACE_INVALID, RestStatus.BAD_REQUEST.getStatus());
        }

        RestResponse fieldValidation =
                this.documentValidations.validateRequiredFields(
                        resource, List.of(Constants.KEY_NAME, Constants.KEY_ENABLED));
        if (fieldValidation != null) return fieldValidation;

        return this.documentValidations.validateMetadataFields(
                resource, List.of(Constants.KEY_TITLE, Constants.KEY_AUTHOR));
    }

    private boolean isValidSpace(String spaceValue) {
        if (spaceValue == null) return false;
        try {
            return validSpaces.contains(Space.fromValue(spaceValue));
        } catch (Exception e) {
            return false;
        }
    }

    @Override
    protected RestResponse syncExternalServices(String id, JsonNode resource) {
        RestResponse engineValidation = this.engine.validateResource(Constants.KEY_FILTER, resource);
        if (engineValidation.getStatus() != RestStatus.OK.getStatus()) {
            return new RestResponse(
                    Constants.E_400_ENGINE_VALIDATION_FAILED + engineValidation.getMessage(),
                    RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }
}
