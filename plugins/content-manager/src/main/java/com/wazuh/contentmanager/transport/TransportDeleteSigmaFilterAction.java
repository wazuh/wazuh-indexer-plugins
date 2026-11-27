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
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.Locale;
import java.util.Set;

import com.wazuh.contentmanager.action.DeleteSigmaFilterAction;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport action for deleting Sigma filter resources, in the Draft space only. The filter is also
 * removed from the Draft policy's {@code sigma_filters} list.
 */
public class TransportDeleteSigmaFilterAction extends AbstractTransportDeleteActionSpaces {

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT);

    @Inject
    public TransportDeleteSigmaFilterAction(
            TransportService transportService, ActionFilters actionFilters, Client client) {
        super(DeleteSigmaFilterAction.NAME, transportService, actionFilters, client);
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
    protected Set<Space> getAllowedSpaces() {
        return validSpaces;
    }

    @Override
    protected void deleteExternalServices(String id, ActionListener<Void> listener) {
        // A Draft filter reaches no external service.
        listener.onResponse(null);
    }

    @Override
    protected void unlinkFromParent(
            Client client, String id, String spaceName, ActionListener<Void> listener) {
        PolicyDocumentWriter.unlink(
                client,
                spaceName,
                Constants.KEY_SIGMA_FILTERS,
                id,
                String.format(Locale.ROOT, Constants.E_500_POLICY_NOT_FOUND_FOR_SPACE, spaceName),
                listener);
    }
}
