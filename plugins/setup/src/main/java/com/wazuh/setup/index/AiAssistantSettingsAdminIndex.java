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

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Privileged access to the AI assistant's providers and settings, stored flat in the shared {@code
 * .wazuh-internal-state} system index — same index content-manager uses for its own credentials,
 * under a separate document this class never reads or exposes. Reachable only through the {@code
 * plugin:wazuh/ai_assistant/settings/{read,write}} gated transport actions.
 */
public class AiAssistantSettingsAdminIndex {

    /** Name of the shared index this class reads and writes. */
    public static final String INDEX_NAME = ".wazuh-internal-state";

    /** Reserved document id holding the settings/field_policy fields. */
    public static final String SETTINGS_DOCUMENT_ID = "wazuh-ai-assistant-settings";

    /** Reserved document id holding content-manager's own credentials. Never touched. */
    private static final String CREDENTIALS_DOCUMENT_ID = "credentials";

    /** Document ids reserved for non-provider documents; never a valid provider id. */
    public static final Set<String> RESERVED_PROVIDER_IDS =
            Set.of(SETTINGS_DOCUMENT_ID, CREDENTIALS_DOCUMENT_ID);

    private static final String PRIVACY_DEFAULT_ON_FIELD = "privacy_default_on";
    private static final String PRIVACY_DEFAULT_PER_PROVIDER_FIELD = "privacy_default_per_provider";
    private static final String USER_CAN_OVERRIDE_FIELD = "user_can_override";
    private static final String FIELD_POLICY_FIELD = "field_policy";

    /** Settings-document fields a {@code PUT} may set; anything else in the body is discarded. */
    private static final Set<String> SETTINGS_FIELDS =
            Set.of(
                    PRIVACY_DEFAULT_ON_FIELD,
                    PRIVACY_DEFAULT_PER_PROVIDER_FIELD,
                    USER_CAN_OVERRIDE_FIELD,
                    FIELD_POLICY_FIELD);

    private static final String UPDATED_AT_FIELD = "updated_at";
    private static final String ID_FIELD = "_id";

    /** Upper bound on the number of provider documents returned by {@link #listProviders}. */
    public static final int MAX_PROVIDERS = 500;

    private final Client client;
    private final ThreadPool threadPool;

    /**
     * Constructor.
     *
     * @param client OpenSearch client.
     * @param threadPool node thread pool, used to stash the calling user's security context.
     */
    public AiAssistantSettingsAdminIndex(Client client, ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
    }

    /**
     * Reads the reserved settings document — {@code privacy_default_on}, {@code
     * privacy_default_per_provider}, {@code user_can_override}, {@code field_policy}, flat at the
     * document root. Missing document yields an empty map. Never includes content-manager's
     * credentials.
     *
     * @param listener receives the document source.
     */
    public void getSettings(ActionListener<Map<String, Object>> listener) {
        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.get(
                    new GetRequest(INDEX_NAME, SETTINGS_DOCUMENT_ID),
                    ActionListener.wrap(
                            response ->
                                    listener.onResponse(response.isExists() ? response.getSourceAsMap() : Map.of()),
                            listener::onFailure));
        }
    }

    /**
     * Lists every provider document — every document in the index except the reserved settings
     * ({@value #SETTINGS_DOCUMENT_ID}) and credentials ({@code "credentials"}) documents.
     *
     * @param listener receives the provider list, each entry carrying its {@code _id}.
     */
    public void listProviders(ActionListener<List<Map<String, Object>>> listener) {
        SearchSourceBuilder source =
                new SearchSourceBuilder()
                        .query(
                                QueryBuilders.boolQuery()
                                        .mustNot(
                                                QueryBuilders.idsQuery()
                                                        .addIds(SETTINGS_DOCUMENT_ID, CREDENTIALS_DOCUMENT_ID)))
                        .size(MAX_PROVIDERS);
        SearchRequest request = new SearchRequest(INDEX_NAME).source(source);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.search(
                    request,
                    ActionListener.wrap(
                            searchResponse -> listener.onResponse(toProviderList(searchResponse)),
                            listener::onFailure));
        }
    }

    private static List<Map<String, Object>> toProviderList(SearchResponse response) {
        List<Map<String, Object>> providers = new ArrayList<>();
        for (SearchHit hit : response.getHits().getHits()) {
            Map<String, Object> provider = new HashMap<>(hit.getSourceAsMap());
            provider.put(ID_FIELD, hit.getId());
            providers.add(provider);
        }
        return providers;
    }

    /**
     * Upserts the reserved settings document with the given {@code privacy_default_on}/{@code
     * privacy_default_per_provider}/{@code user_can_override}/{@code field_policy} keys, discarding
     * anything else the caller sent.
     *
     * @param body the client-supplied body; only its known settings-document keys are persisted.
     * @param listener receives the index response.
     */
    public void putSettings(Map<String, Object> body, ActionListener<IndexResponse> listener) {
        Map<String, Object> source = new HashMap<>();
        for (String field : SETTINGS_FIELDS) {
            if (body.containsKey(field)) {
                source.put(field, body.get(field));
            }
        }
        IndexRequest request =
                new IndexRequest(INDEX_NAME)
                        .id(SETTINGS_DOCUMENT_ID)
                        .source(source, XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.index(request, listener);
        }
    }

    /**
     * Creates or updates a provider document. Stamps {@code updated_at} with the current time,
     * overwriting any value the caller sent.
     *
     * @param id provider document id. The caller (create with a client-supplied UUID, or update by
     *     path id) is responsible for resolving this before calling; never null or blank.
     * @param provider the provider fields to persist, flat at the document root.
     * @param listener receives the index response.
     */
    public void putProvider(
            String id, Map<String, Object> provider, ActionListener<IndexResponse> listener) {
        Map<String, Object> source = new HashMap<>(provider);
        source.put(UPDATED_AT_FIELD, Instant.now().toString());
        IndexRequest request =
                new IndexRequest(INDEX_NAME)
                        .id(id)
                        .source(source, XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.index(request, listener);
        }
    }

    /**
     * Deletes a provider document by id.
     *
     * @param id provider document id to delete.
     * @param listener receives the delete response; fails with a {@link ResourceNotFoundException}
     *     when no provider exists with that id.
     */
    public void deleteProvider(String id, ActionListener<DeleteResponse> listener) {
        DeleteRequest request =
                new DeleteRequest(INDEX_NAME, id).setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.delete(
                    request,
                    ActionListener.wrap(
                            response -> {
                                if (response.getResult() == DocWriteResponse.Result.NOT_FOUND) {
                                    listener.onFailure(new ResourceNotFoundException("Provider not found: " + id));
                                    return;
                                }
                                listener.onResponse(response);
                            },
                            listener::onFailure));
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
