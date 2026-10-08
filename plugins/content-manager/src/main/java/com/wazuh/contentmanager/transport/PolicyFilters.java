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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.transport.client.Client;

import java.util.Locale;
import java.util.function.Predicate;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Adds a filter id to, or removes one from, the {@code filters} list of a space's policy.
 *
 * <p>Every change is a read-modify-write of the whole policy document, which other requests may be
 * changing at the same time: a filter create and a filter delete in the same space are not
 * serialized by anything else. Writers are therefore serialized optimistically, as in {@code
 * UserOverridesService}: the policy is written with the {@code ifSeqNo}/{@code ifPrimaryTerm} it
 * was read with, and a version conflict re-reads it and applies the change again to the winner's
 * document, up to {@link Constants#POLICY_FILTERS_MAX_UPDATE_ATTEMPTS} times.
 */
final class PolicyFilters {

    private static final Logger log = LogManager.getLogger(PolicyFilters.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private PolicyFilters() {}

    /**
     * Appends {@code filterId} to the policy of {@code spaceName}, unless it is already listed.
     *
     * @param client OpenSearch client.
     * @param spaceName the space whose policy lists the filter.
     * @param filterId the filter's document id.
     * @param listener notified once the policy has been written, or fails with an {@link
     *     IllegalStateException} when the space has no policy.
     */
    static void link(
            Client client, String spaceName, String filterId, ActionListener<Void> listener) {
        update(
                client,
                spaceName,
                filters -> {
                    for (JsonNode existing : filters) {
                        if (existing.asText().equals(filterId)) {
                            return false;
                        }
                    }
                    filters.add(filterId);
                    return true;
                },
                1,
                listener);
    }

    /**
     * Removes every occurrence of {@code filterId} from the policy of {@code spaceName}. A policy
     * that does not list it is left untouched.
     *
     * @param client OpenSearch client.
     * @param spaceName the space whose policy lists the filter.
     * @param filterId the filter's document id.
     * @param listener notified once the policy has been written, or fails with an {@link
     *     IllegalStateException} when the space has no policy.
     */
    static void unlink(
            Client client, String spaceName, String filterId, ActionListener<Void> listener) {
        update(
                client,
                spaceName,
                filters -> {
                    boolean removed = false;
                    for (int i = filters.size() - 1; i >= 0; i--) {
                        if (filters.get(i).asText().equals(filterId)) {
                            filters.remove(i);
                            removed = true;
                        }
                    }
                    return removed;
                },
                1,
                listener);
    }

    /**
     * One read-modify-write attempt.
     *
     * <p>The search only locates the policy's document id. Its source and sequence number are then
     * read with a realtime get, so that a retry sees the write that beat it even before the index is
     * refreshed.
     *
     * @param mutator changes the policy's {@code filters} list in place and returns whether it
     *     changed anything; when it did not, nothing is written.
     */
    private static void update(
            Client client,
            String spaceName,
            Predicate<ArrayNode> mutator,
            int attempt,
            ActionListener<Void> listener) {
        SearchRequest search =
                new SearchRequest(Constants.INDEX_POLICIES)
                        .source(
                                new SearchSourceBuilder()
                                        .query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, spaceName))
                                        .fetchSource(false)
                                        .size(1));

        client.search(
                search,
                ActionListener.wrap(
                        searchResponse -> {
                            SearchHit[] hits = searchResponse.getHits().getHits();
                            if (hits.length == 0) {
                                listener.onFailure(policyNotFound(spaceName));
                                return;
                            }
                            client.get(
                                    new GetRequest(Constants.INDEX_POLICIES, hits[0].getId()),
                                    ActionListener.wrap(
                                            policy -> write(client, spaceName, mutator, attempt, policy, listener),
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    private static void write(
            Client client,
            String spaceName,
            Predicate<ArrayNode> mutator,
            int attempt,
            GetResponse policy,
            ActionListener<Void> listener)
            throws Exception {
        if (!policy.isExists()) {
            // Deleted between the search and the get, e.g. by a space reset.
            listener.onFailure(policyNotFound(spaceName));
            return;
        }

        ObjectNode wrapper = (ObjectNode) MAPPER.readTree(policy.getSourceAsString());
        ObjectNode document = (ObjectNode) wrapper.get(Constants.KEY_DOCUMENT);
        JsonNode current = document.get(Constants.KEY_FILTERS);
        ArrayNode filters =
                current instanceof ArrayNode array ? array : document.putArray(Constants.KEY_FILTERS);

        if (!mutator.test(filters)) {
            listener.onResponse(null);
            return;
        }

        String hash = Resource.computeSha256(document.toString());
        ((ObjectNode) wrapper.at("/hash")).put(Constants.KEY_SHA256, hash);

        IndexRequest request =
                new ContentIndex(client, Constants.INDEX_POLICIES)
                        .prepareCreateRequest(policy.getId(), wrapper, WriteRequest.RefreshPolicy.IMMEDIATE)
                        .setIfSeqNo(policy.getSeqNo())
                        .setIfPrimaryTerm(policy.getPrimaryTerm());

        client.index(
                request,
                ActionListener.wrap(
                        indexed -> listener.onResponse(null),
                        e -> {
                            boolean conflict =
                                    ExceptionsHelper.unwrap(e, VersionConflictEngineException.class) != null;
                            if (conflict && attempt < Constants.POLICY_FILTERS_MAX_UPDATE_ATTEMPTS) {
                                log.debug(Constants.D_LOG_POLICY_FILTERS_CONFLICT, spaceName, attempt);
                                update(client, spaceName, mutator, attempt + 1, listener);
                                return;
                            }
                            listener.onFailure(e);
                        }));
    }

    private static IllegalStateException policyNotFound(String spaceName) {
        return new IllegalStateException(
                String.format(Locale.ROOT, Constants.E_500_POLICY_NOT_FOUND_FOR_SPACE, spaceName));
    }
}
