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
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import com.wazuh.contentmanager.action.TriggerUpdateAction;
import com.wazuh.contentmanager.action.TriggerUpdateRequest;
import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.jobscheduler.jobs.CatalogSyncJob;

public class TransportTriggerUpdateAction
        extends HandledTransportAction<TriggerUpdateRequest, MessageStatusResponse> {

    private final CatalogSyncJob catalogSyncJob;

    @Inject
    public TransportTriggerUpdateAction(
            TransportService transportService,
            ActionFilters actionFilters,
            CatalogSyncJob catalogSyncJob) {
        super(TriggerUpdateAction.NAME, transportService, actionFilters, TriggerUpdateRequest::new);
        this.catalogSyncJob = catalogSyncJob;
    }

    @Override
    protected void doExecute(
            Task task, TriggerUpdateRequest request, ActionListener<MessageStatusResponse> listener) {
        try {
            if (this.catalogSyncJob.isRunning()) {
                listener.onResponse(
                        new MessageStatusResponse(
                                "A content update is already in progress.", RestStatus.CONFLICT));
                return;
            }
            this.catalogSyncJob.trigger();
            listener.onResponse(
                    new MessageStatusResponse(
                            "The update request has been accepted for processing.", RestStatus.ACCEPTED));
        } catch (Exception e) {
            listener.onResponse(
                    new MessageStatusResponse(
                            e.getMessage() != null
                                    ? e.getMessage()
                                    : "An unexpected error occurred while processing your request.",
                            RestStatus.INTERNAL_SERVER_ERROR));
        }
    }
}
