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

import java.util.Set;

import com.wazuh.contentmanager.action.DeleteFilterAction;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.utils.Constants;

/** Transport action for deleting Filter resources (Spaces variant). */
public class TransportDeleteFilterAction extends AbstractTransportDeleteActionSpaces {

    private static final Set<Space> validSpaces = Set.of(Space.DRAFT, Space.STANDARD);

    private final UserOverridesService userOverridesService;

    @Inject
    public TransportDeleteFilterAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine,
            EngineContentLoader engineContentLoader,
            UserOverridesService userOverridesService) {
        super(
                DeleteFilterAction.NAME,
                transportService,
                actionFilters,
                client,
                engine,
                engineContentLoader);
        this.userOverridesService = userOverridesService;
    }

    @Override
    protected void afterResourceDeleted(String id, String spaceName, Runnable onDone) {
        OverrideRecorder.record(
                this.userOverridesService,
                spaceName,
                UserOverridesService.removeFilter(id),
                id,
                Constants.KEY_FILTER,
                onDone);
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
    protected Set<Space> getAllowedSpaces() {
        return validSpaces;
    }

    @Override
    protected void deleteExternalServices(String id, ActionListener<Void> listener) {
        // Not applicable for this implementation.
        listener.onResponse(null);
    }

    @Override
    protected void unlinkFromParent(
            Client client, String id, String spaceName, ActionListener<Void> listener) {
        PolicyFilters.unlink(client, spaceName, id, listener);
    }
}
