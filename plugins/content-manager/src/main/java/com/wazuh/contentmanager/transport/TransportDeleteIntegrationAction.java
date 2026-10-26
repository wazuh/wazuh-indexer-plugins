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

import java.util.Locale;

import com.wazuh.contentmanager.action.DeleteIntegrationAction;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for deleting Integration resources. */
public class TransportDeleteIntegrationAction extends AbstractTransportDeleteAction {

    @Inject
    public TransportDeleteIntegrationAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(DeleteIntegrationAction.NAME, transportService, actionFilters, client, engine);
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
    protected void validateDelete(
            Client client,
            String id,
            com.wazuh.contentmanager.cti.catalog.service.SpaceService spaceService,
            ActionListener<RestResponse> listener) {
        ContentIndex index = new ContentIndex(client, Constants.INDEX_INTEGRATIONS, null);
        JsonNode doc = index.getDocument(id);

        if (doc != null && doc.has(Constants.KEY_DOCUMENT)) {
            JsonNode document = doc.get(Constants.KEY_DOCUMENT);
            // Protected integrations cannot be deleted, regardless of the space they live in.
            if (this.documentValidations.isProtected(document)) {
                listener.onResponse(
                        new RestResponse(
                                String.format(Locale.ROOT, Constants.E_400_PROTECTED_INTEGRATION, id),
                                RestStatus.BAD_REQUEST.getStatus()));
                return;
            }
            if (isListNotEmpty(document.get(Constants.KEY_DECODERS))) {
                listener.onResponse(
                        new RestResponse(
                                String.format(
                                        Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_DECODERS),
                                RestStatus.BAD_REQUEST.getStatus()));
                return;
            }
            if (isListNotEmpty(document.get(Constants.KEY_RULES))) {
                listener.onResponse(
                        new RestResponse(
                                String.format(
                                        Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_RULES),
                                RestStatus.BAD_REQUEST.getStatus()));
                return;
            }
            if (isListNotEmpty(document.get(Constants.KEY_KVDBS))) {
                listener.onResponse(
                        new RestResponse(
                                String.format(
                                        Locale.ROOT, Constants.E_400_INTEGRATION_HAS_RESOURCES, Constants.KEY_KVDBS),
                                RestStatus.BAD_REQUEST.getStatus()));
                return;
            }
        }
        listener.onResponse(null);
    }

    @Override
    protected void deleteExternalServices(
            String id, SecurityAnalyticsService securityAnalyticsService, ActionListener<Void> listener) {
        securityAnalyticsService.deleteIntegration(
                id,
                Space.DRAFT,
                ActionListener.wrap(response -> listener.onResponse(null), listener::onFailure));
    }

    @Override
    protected void unlinkFromParent(
            Client client,
            String id,
            IntegrationService integrationService,
            ActionListener<Void> listener) {
        PolicyLinks.unlink(
                client,
                Space.DRAFT.toString(),
                Constants.KEY_INTEGRATIONS,
                id,
                Constants.E_500_MISSING_DRAFT_POLICY,
                listener);
    }

    private boolean isListNotEmpty(JsonNode node) {
        return node != null && node.isArray() && !node.isEmpty();
    }
}
