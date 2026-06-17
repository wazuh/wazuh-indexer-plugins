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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.IOException;
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
        super(
                DeleteDecoderAction.NAME,
                transportService,
                actionFilters,
                client,
                engine);
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
    protected RestResponse validateDelete(Client client, String id, SpaceService spaceService) {
        try {
            Map<String, Object> policySource = spaceService.getPolicy(Space.DRAFT.toString());

            if (policySource != null && policySource.containsKey(Constants.KEY_DOCUMENT)) {
                @SuppressWarnings("unchecked")
                Map<String, Object> document =
                        (Map<String, Object>) policySource.get(Constants.KEY_DOCUMENT);

                if (document != null && id.equals(document.get("root_decoder"))) {
                    return new RestResponse(
                            String.format(Locale.ROOT, Constants.E_400_CANNOT_REMOVE_ROOT_DECODER, id),
                            RestStatus.BAD_REQUEST.getStatus());
                }
            }
        } catch (Exception e) {
            return new RestResponse(
                    Constants.E_500_INTERNAL_SERVER_ERROR,
                    RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
        return null;
    }

    @Override
    protected void deleteExternalServices(
            String id, SecurityAnalyticsService securityAnalyticsService) {
        // Decoders are not explicitly deleted from Engine or SAP
    }

    @Override
    protected void unlinkFromParent(
            Client client, String id, IntegrationService integrationService) throws IOException {
        integrationService.unlinkResourceFromIntegrations(id, Constants.KEY_DECODERS);
    }
}
