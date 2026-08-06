/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.ActionRequest;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilter;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.tasks.Task;

import java.util.HashMap;
import java.util.Map;

/**
 * Stamps every document written to <code>.wazuh-ai-assistant-settings*</code> with the backend roles
 * allowed to read it, overwriting whatever the client sent.
 *
 * <p>The field is what the Document Level Security query of the {@code wazuh_ai_assistant_settings}
 * security role matches on, so the read isolation of the AI provider credentials depends on it being
 * present and trustworthy. Setting it here rather than trusting the clients keeps that out of the
 * document contract: a write that reaches the index always carries the right value.
 *
 * @see AIAssistantSettingsIndex
 */
public class AIAssistantSettingsVisibilityFilter implements ActionFilter {
    private static final Logger log = LogManager.getLogger(AIAssistantSettingsVisibilityFilter.class);

    /** Runs before any other filter, so no other component observes the un-stamped document. */
    @Override
    public int order() {
        return Integer.MIN_VALUE;
    }

    @Override
    public <Request extends ActionRequest, Response extends ActionResponse> void apply(
            Task task,
            String action,
            Request request,
            ActionRequestMetadata<Request, Response> metadata,
            ActionListener<Response> listener,
            ActionFilterChain<Request, Response> chain) {
        if (request instanceof IndexRequest) {
            stamp((IndexRequest) request);
        } else if (request instanceof UpdateRequest) {
            stamp((UpdateRequest) request);
        } else if (request instanceof BulkRequest) {
            for (DocWriteRequest<?> documentRequest : ((BulkRequest) request).requests()) {
                if (documentRequest instanceof IndexRequest) {
                    stamp((IndexRequest) documentRequest);
                } else if (documentRequest instanceof UpdateRequest) {
                    stamp((UpdateRequest) documentRequest);
                }
            }
        }
        chain.proceed(task, action, request, listener);
    }

    /**
     * Stamps the partial document and the upsert document of an update request. A partial update
     * merges into the stored source, which already holds the field, but an upsert creates a document
     * from scratch and would otherwise be visible to nobody.
     *
     * <p>The index is read from the update request itself: the {@link IndexRequest} instances it
     * wraps carry no index name of their own.
     *
     * @param request the update request to stamp.
     */
    private void stamp(UpdateRequest request) {
        if (!targetsSettingsIndex(request.index())) {
            return;
        }
        if (request.doc() != null) {
            stampSource(request.doc(), request.index());
        }
        if (request.upsertRequest() != null) {
            stampSource(request.upsertRequest(), request.index());
        }
    }

    /**
     * Stamps an index request aimed at the AI assistant settings index. Requests targeting any other
     * index are left untouched.
     *
     * @param request the index request to stamp.
     */
    private void stamp(IndexRequest request) {
        if (!targetsSettingsIndex(request.index())) {
            return;
        }
        stampSource(request, request.index());
    }

    /**
     * Returns whether an index name belongs to the AI assistant settings index.
     *
     * @param index the index name to test, may be null.
     * @return true when the write must be stamped.
     */
    private boolean targetsSettingsIndex(String index) {
        return index != null && index.startsWith(AIAssistantSettingsIndex.INDEX_NAME);
    }

    /**
     * Overwrites the visibility field of a document, discarding any value the client sent.
     *
     * @param request the request holding the document source.
     * @param index the index the document is written to, for logging.
     */
    private void stampSource(IndexRequest request, String index) {
        try {
            Map<String, Object> source = new HashMap<>(request.sourceAsMap());
            source.put(AIAssistantSettingsIndex.VISIBILITY_FIELD, AIAssistantSettingsIndex.VISIBLE_TO);
            request.source(source, request.getContentType());
        } catch (Exception e) {
            // Leave the request untouched: the document is then written without the field, which makes
            // it unreadable for everyone rather than readable by everyone.
            log.error(
                    "Could not set [{}] on a document of [{}]: {}",
                    AIAssistantSettingsIndex.VISIBILITY_FIELD,
                    index,
                    e.toString());
        }
    }
}
