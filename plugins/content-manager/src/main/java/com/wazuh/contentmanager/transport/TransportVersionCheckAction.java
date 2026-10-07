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
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import com.wazuh.contentmanager.action.VersionCheckAction;
import com.wazuh.contentmanager.action.VersionCheckRequest;
import com.wazuh.contentmanager.action.VersionCheckResponse;
import com.wazuh.contentmanager.cti.catalog.service.VersionCheckService;

/**
 * Transport action for GET /version/check. Queries the CTI API to determine available Wazuh version
 * updates and returns the result as structured JSON.
 *
 * <p>The work is delegated to {@link VersionCheckService}, which runs the blocking CTI call off the
 * transport thread and caches and coalesces checks.
 */
public class TransportVersionCheckAction
        extends HandledTransportAction<VersionCheckRequest, VersionCheckResponse> {

    private final VersionCheckService versionCheckService;

    @Inject
    public TransportVersionCheckAction(
            TransportService transportService,
            ActionFilters actionFilters,
            VersionCheckService versionCheckService) {
        super(VersionCheckAction.NAME, transportService, actionFilters, VersionCheckRequest::new);
        this.versionCheckService = versionCheckService;
    }

    @Override
    protected void doExecute(
            Task task, VersionCheckRequest request, ActionListener<VersionCheckResponse> listener) {
        this.versionCheckService.check(listener);
    }
}
