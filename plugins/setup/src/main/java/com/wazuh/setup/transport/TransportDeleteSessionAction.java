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
package com.wazuh.setup.transport;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import com.wazuh.setup.action.DeleteSessionAction;
import com.wazuh.setup.action.DeleteSessionRequest;
import com.wazuh.setup.action.DeleteSessionResponse;
import com.wazuh.setup.index.AiAssistantSessionsAdminIndex;

/**
 * Transport action that deletes an AI assistant session regardless of which user owns it. Gated by
 * {@link DeleteSessionAction#NAME} as a cluster permission; the underlying delete bypasses the
 * per-owner Document Level Security via {@link AiAssistantSessionsAdminIndex}.
 */
public class TransportDeleteSessionAction
        extends HandledTransportAction<DeleteSessionRequest, DeleteSessionResponse> {
    private static final Logger log = LogManager.getLogger(TransportDeleteSessionAction.class);

    private final AiAssistantSessionsAdminIndex sessionsAdminIndex;

    @Inject
    public TransportDeleteSessionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            AiAssistantSessionsAdminIndex sessionsAdminIndex) {
        super(DeleteSessionAction.NAME, transportService, actionFilters, DeleteSessionRequest::new);
        this.sessionsAdminIndex = sessionsAdminIndex;
    }

    @Override
    protected void doExecute(
            Task task, DeleteSessionRequest request, ActionListener<DeleteSessionResponse> listener) {
        this.sessionsAdminIndex.delete(
                request.getId(),
                new ActionListener<>() {
                    @Override
                    public void onResponse(BulkByScrollResponse response) {
                        if (response.getDeleted() == 0) {
                            listener.onResponse(
                                    new DeleteSessionResponse("Session not found.", RestStatus.NOT_FOUND));
                            return;
                        }
                        listener.onResponse(new DeleteSessionResponse("Session deleted.", RestStatus.OK));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error(
                                "Failed to delete AI assistant session [{}]: {}",
                                request.getId(),
                                e.getMessage(),
                                e);
                        listener.onFailure(e);
                    }
                });
    }
}
