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
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.action.CreateSigmaFilterAction;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SigmaFilterService;
import com.wazuh.contentmanager.cti.catalog.utils.SigmaFilterComposer;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport action for creating Sigma filter resources. A Sigma filter is created in the Draft
 * space and linked to the Draft policy's {@code sigma_filters} list.
 */
public class TransportCreateSigmaFilterAction extends AbstractTransportCreateActionSpaces {

    private final SigmaFilterService sigmaFilterService;

    @Inject
    public TransportCreateSigmaFilterAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(CreateSigmaFilterAction.NAME, transportService, actionFilters, client, engine);
        this.sigmaFilterService = new SigmaFilterService(client);
    }

    @Override
    protected boolean requiresIntegrationId() {
        return false;
    }

    @Override
    protected String getIndexName() {
        return Constants.INDEX_SIGMA_FILTERS;
    }

    @Override
    protected String getResourceType() {
        return Constants.KEY_SIGMA_FILTER;
    }

    @Override
    protected String getSpaceName(JsonNode root) {
        return root.path(Constants.KEY_SPACE).asText();
    }

    @Override
    protected RestResponse validatePayload(Client client, JsonNode root, JsonNode resource) {
        if (resource.has(Constants.KEY_ID)) {
            return new RestResponse(
                    Constants.E_400_UUID_SHOULD_NOT_BE_PROVIDED, RestStatus.BAD_REQUEST.getStatus());
        }
        return validateSigmaFilter(root, resource, this.documentValidations);
    }

    /**
     * Validates a Sigma filter payload on its own: the Draft space, its title and its structure.
     *
     * @param root the request payload.
     * @param resource the filter document.
     * @param validations the payload validations.
     * @return the 400 response describing the problem, or {@code null} if the filter is valid.
     */
    static RestResponse validateSigmaFilter(
            JsonNode root, JsonNode resource, PayloadValidations validations) {
        if (!Space.DRAFT.toString().equals(root.path(Constants.KEY_SPACE).asText(null))) {
            return new RestResponse(
                    Constants.E_400_RESOURCE_SPACE_INVALID, RestStatus.BAD_REQUEST.getStatus());
        }
        RestResponse metadataValidation =
                validations.validateMetadataFields(resource, List.of(Constants.KEY_TITLE));
        if (metadataValidation != null) {
            return metadataValidation;
        }
        try {
            SigmaFilterComposer.validateFilter(resource);
        } catch (SigmaFilterComposer.ComposeException e) {
            return new RestResponse(e.getMessage(), RestStatus.BAD_REQUEST.getStatus());
        }
        return null;
    }

    @Override
    protected int getMaxAllowed() {
        return PluginSettings.getInstance().getMaxSigmaFilters();
    }

    @Override
    protected String getTooManyResourcesMessageFormat() {
        return Constants.E_400_TOO_MANY_SIGMA_FILTERS;
    }

    @Override
    protected String getMaxReachedLogFormat() {
        return Constants.I_LOG_MAX_SIGMA_FILTERS_REACHED;
    }

    @Override
    protected void syncExternalServices(
            String id, JsonNode resource, ActionListener<RestResponse> listener) {
        this.sigmaFilterService.checkTargets(
                resource,
                Space.DRAFT,
                ActionListener.wrap(
                        error ->
                                listener.onResponse(
                                        error == null
                                                ? null
                                                : new RestResponse(error, RestStatus.BAD_REQUEST.getStatus())),
                        listener::onFailure));
    }

    @Override
    protected void linkToParent(
            Client client, String id, JsonNode root, String spaceName, ActionListener<Void> listener) {
        PolicyDocumentWriter.link(
                client,
                spaceName,
                Constants.KEY_SIGMA_FILTERS,
                id,
                String.format(Locale.ROOT, Constants.E_500_POLICY_NOT_FOUND_FOR_SPACE, spaceName),
                listener);
    }
}
