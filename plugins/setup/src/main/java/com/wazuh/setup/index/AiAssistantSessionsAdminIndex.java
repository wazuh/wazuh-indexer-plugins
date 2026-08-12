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
package com.wazuh.setup.index;

import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.DeleteByQueryAction;
import org.opensearch.index.reindex.DeleteByQueryRequest;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

/**
 * Privileged access to the {@code wazuh-ai-assistant-sessions} data stream, bypassing the per-owner
 * Document Level Security that normally keeps every user from reading anyone else's conversations.
 */
public class AiAssistantSessionsAdminIndex {

    /** Name of the data stream this class reads and writes. */
    public static final String INDEX_NAME = "wazuh-ai-assistant-sessions";

    /** Upper bound on the page size a caller may request, to avoid unbounded result sets. */
    public static final int MAX_SEARCH_SIZE = 500;

    private final Client client;
    private final ThreadPool threadPool;

    /**
     * Constructor.
     *
     * @param client OpenSearch client.
     * @param threadPool node thread pool, used to stash the calling user's security context.
     */
    public AiAssistantSessionsAdminIndex(Client client, ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
    }

    /**
     * Searches sessions across every user, optionally restricted to one.
     *
     * @param user username to filter by, or {@code null}/blank for every user's sessions.
     * @param size maximum number of documents to return, clamped to {@link #MAX_SEARCH_SIZE}.
     * @param listener receives the raw search response.
     */
    public void search(String user, int size, ActionListener<SearchResponse> listener) {
        SearchSourceBuilder source =
                new SearchSourceBuilder()
                        .query(
                                user == null || user.isBlank()
                                        ? QueryBuilders.matchAllQuery()
                                        : QueryBuilders.termQuery("user", user))
                        .size(Math.max(1, Math.min(size, MAX_SEARCH_SIZE)));
        SearchRequest request = new SearchRequest(INDEX_NAME).source(source);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.search(request, listener);
        }
    }

    /**
     * Deletes a single session document by id, regardless of which user owns it.
     *
     * @param id document id of the session to delete.
     * @param listener receives the outcome of the delete-by-query.
     */
    public void delete(String id, ActionListener<BulkByScrollResponse> listener) {
        DeleteByQueryRequest request =
                new DeleteByQueryRequest(INDEX_NAME).setQuery(QueryBuilders.idsQuery().addIds(id));

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.execute(DeleteByQueryAction.INSTANCE, request, listener);
        }
    }

    /**
     * Stashes the calling user's security context so the subsequent client call runs with this
     * plugin's own privileges instead of the caller's.
     *
     * @return the stored context, auto-restored on close.
     */
    private ThreadContext.StoredContext stashContext() {
        return this.threadPool.getThreadContext().stashContext();
    }
}
