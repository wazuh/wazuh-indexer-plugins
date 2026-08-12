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
import org.opensearch.search.SearchHit;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.action.SearchSessionsAction;
import com.wazuh.setup.action.SearchSessionsRequest;
import com.wazuh.setup.action.SearchSessionsResponse;
import com.wazuh.setup.index.AiAssistantSessionsAdminIndex;

/**
 * Transport action that searches AI assistant sessions across every user. Gated by {@link
 * SearchSessionsAction#NAME} as a cluster permission; the underlying search bypasses the per-owner
 * Document Level Security via {@link AiAssistantSessionsAdminIndex}.
 */
public class TransportSearchSessionsAction
        extends HandledTransportAction<SearchSessionsRequest, SearchSessionsResponse> {
    private static final Logger log = LogManager.getLogger(TransportSearchSessionsAction.class);

    private final AiAssistantSessionsAdminIndex sessionsAdminIndex;

    @Inject
    public TransportSearchSessionsAction(
            TransportService transportService,
            ActionFilters actionFilters,
            AiAssistantSessionsAdminIndex sessionsAdminIndex) {
        super(SearchSessionsAction.NAME, transportService, actionFilters, SearchSessionsRequest::new);
        this.sessionsAdminIndex = sessionsAdminIndex;
    }

    @Override
    protected void doExecute(
            Task task, SearchSessionsRequest request, ActionListener<SearchSessionsResponse> listener) {
        this.sessionsAdminIndex.search(
                request.getUser(),
                request.getSize(),
                new ActionListener<>() {
                    @Override
                    public void onResponse(org.opensearch.action.search.SearchResponse response) {
                        List<Map<String, Object>> sessions = new ArrayList<>();
                        for (SearchHit hit : response.getHits().getHits()) {
                            Map<String, Object> source = hit.getSourceAsMap();
                            source.put("_id", hit.getId());
                            sessions.add(source);
                        }
                        listener.onResponse(
                                new SearchSessionsResponse(response.getHits().getTotalHits().value(), sessions));
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to search AI assistant sessions: {}", e.getMessage(), e);
                        listener.onFailure(e);
                    }
                });
    }
}
