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

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.Locale;
import java.util.Map;

import com.wazuh.contentmanager.action.DeleteDecoderAction;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for deleting Decoder resources. */
public class TransportDeleteDecoderAction extends AbstractTransportDeleteAction {

    @Inject
    public TransportDeleteDecoderAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(DeleteDecoderAction.NAME, transportService, actionFilters, client, engine);
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
    protected void validateDelete(
            Client client, String id, SpaceService spaceService, ActionListener<RestResponse> listener) {
        spaceService.getPolicy(
                Space.DRAFT.toString(),
                ActionListener.wrap(
                        policySource -> {
                            if (policySource != null && policySource.containsKey(Constants.KEY_DOCUMENT)) {
                                @SuppressWarnings("unchecked")
                                Map<String, Object> document =
                                        (Map<String, Object>) policySource.get(Constants.KEY_DOCUMENT);

                                if (document != null && id.equals(document.get("root_decoder"))) {
                                    listener.onResponse(
                                            new RestResponse(
                                                    String.format(
                                                            Locale.ROOT, Constants.E_400_CANNOT_REMOVE_ROOT_DECODER, id),
                                                    RestStatus.BAD_REQUEST.getStatus()));
                                    return;
                                }
                            }
                            listener.onResponse(null);
                        },
                        e ->
                                listener.onResponse(
                                        new RestResponse(
                                                Constants.E_500_INTERNAL_SERVER_ERROR,
                                                RestStatus.INTERNAL_SERVER_ERROR.getStatus()))));
    }

    @Override
    protected void deleteExternalServices(
            String id, SecurityAnalyticsService securityAnalyticsService, ActionListener<Void> listener) {
        // Decoders are not explicitly deleted from Engine or SAP
        listener.onResponse(null);
    }

    @Override
    protected void unlinkFromParent(
            Client client,
            String id,
            IntegrationService integrationService,
            ActionListener<Void> listener) {
        try {
            integrationService.unlinkResourceFromIntegrations(id, Constants.KEY_DECODERS);
            listener.onResponse(null);
        } catch (Exception e) {
            listener.onFailure(e);
        }
    }
}
