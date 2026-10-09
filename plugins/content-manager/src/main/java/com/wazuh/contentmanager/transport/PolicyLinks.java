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
import org.opensearch.common.Randomness;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.ArrayDeque;
import java.util.Deque;
import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Consumer;
import java.util.function.Predicate;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Adds a resource id to, or removes one from, one of the id lists of a space's policy: {@code
 * filters} or {@code integrations}.
 *
 * <p>Every change is a read-modify-write of the whole policy document, which other requests may be
 * changing at the same time: filter and integration creates and deletes all rewrite the same draft
 * policy. Two layers keep their changes from overwriting each other:
 *
 * <ul>
 *   <li>Within a node, the changes to one space's policy run one at a time, in arrival order. A
 *       burst of concurrent requests therefore causes no conflicts among themselves, however many
 *       there are.
 *   <li>Across nodes, and against the other writers of the policy document (the space hash update,
 *       for one), the policy is written with the {@code ifSeqNo}/{@code ifPrimaryTerm} it was read
 *       with, as in {@code UserOverridesService}. A version conflict re-reads it and applies the
 *       change again to the winner's document, after a randomized exponential backoff, up to {@link
 *       Constants#POLICY_LINKS_MAX_UPDATE_ATTEMPTS} times.
 * </ul>
 *
 * <p>Every writer of these lists must go through here: a single unguarded writer overwrites the
 * others' changes.
 */
final class PolicyLinks {

    private static final Logger log = LogManager.getLogger(PolicyLinks.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The per-space queues of this node's pending changes, keyed by space name. */
    private static final ConcurrentMap<String, SpaceQueue> QUEUES = new ConcurrentHashMap<>();

    private PolicyLinks() {}

    /**
     * Appends {@code id} to the {@code listKey} list of the policy of {@code spaceName}, unless it is
     * already listed.
     *
     * @param client OpenSearch client.
     * @param spaceName the space whose policy lists the resource.
     * @param listKey the policy document's list, {@link Constants#KEY_FILTERS} or {@link
     *     Constants#KEY_INTEGRATIONS}.
     * @param id the resource's document id.
     * @param missingPolicyMessage message of the {@link IllegalStateException} the listener fails
     *     with when the space has no policy.
     * @param listener notified once the policy has been written.
     */
    static void link(
            Client client,
            String spaceName,
            String listKey,
            String id,
            String missingPolicyMessage,
            ActionListener<Void> listener) {
        submit(
                client,
                new Target(spaceName, listKey, missingPolicyMessage),
                ids -> {
                    for (JsonNode existing : ids) {
                        if (existing.asText().equals(id)) {
                            return false;
                        }
                    }
                    ids.add(id);
                    return true;
                },
                listener);
    }

    /**
     * Removes every occurrence of {@code id} from the {@code listKey} list of the policy of {@code
     * spaceName}. A policy that does not list it is left untouched.
     *
     * @param client OpenSearch client.
     * @param spaceName the space whose policy lists the resource.
     * @param listKey the policy document's list, {@link Constants#KEY_FILTERS} or {@link
     *     Constants#KEY_INTEGRATIONS}.
     * @param id the resource's document id.
     * @param missingPolicyMessage message of the {@link IllegalStateException} the listener fails
     *     with when the space has no policy.
     * @param listener notified once the policy has been written.
     */
    static void unlink(
            Client client,
            String spaceName,
            String listKey,
            String id,
            String missingPolicyMessage,
            ActionListener<Void> listener) {
        submit(
                client,
                new Target(spaceName, listKey, missingPolicyMessage),
                ids -> {
                    boolean removed = false;
                    for (int i = ids.size() - 1; i >= 0; i--) {
                        if (ids.get(i).asText().equals(id)) {
                            ids.remove(i);
                            removed = true;
                        }
                    }
                    return removed;
                },
                listener);
    }

    /** Which list of which space's policy is being changed, and how to report a missing policy. */
    private record Target(String spaceName, String listKey, String missingPolicyMessage) {}

    /**
     * Queues the change behind the ones already pending for the same space on this node. The queue
     * moves on as soon as the change is written or has failed, before {@code listener} is notified.
     */
    private static void submit(
            Client client, Target target, Predicate<ArrayNode> mutator, ActionListener<Void> listener) {
        QUEUES
                .computeIfAbsent(target.spaceName(), k -> new SpaceQueue())
                .submit(
                        done ->
                                update(
                                        client,
                                        target,
                                        mutator,
                                        1,
                                        ActionListener.wrap(
                                                v -> {
                                                    done.run();
                                                    listener.onResponse(null);
                                                },
                                                e -> {
                                                    done.run();
                                                    listener.onFailure(e);
                                                })));
    }

    /**
     * Runs asynchronous operations one at a time, in submission order. An operation receives a
     * callback to run once it has finished, which starts the next one.
     */
    static final class SpaceQueue {
        private final Deque<Consumer<Runnable>> pending = new ArrayDeque<>();
        private boolean running;

        void submit(Consumer<Runnable> operation) {
            synchronized (this) {
                this.pending.add(operation);
                if (this.running) {
                    return;
                }
                this.running = true;
            }
            this.runNext();
        }

        private void runNext() {
            Consumer<Runnable> operation;
            synchronized (this) {
                operation = this.pending.poll();
                if (operation == null) {
                    this.running = false;
                    return;
                }
            }
            AtomicBoolean finished = new AtomicBoolean();
            Runnable done =
                    () -> {
                        if (finished.compareAndSet(false, true)) {
                            this.runNext();
                        }
                    };
            try {
                operation.accept(done);
            } catch (RuntimeException e) {
                // An operation that throws before reaching its callback must not stall the queue.
                log.error(Constants.E_LOG_POLICY_LINKS_OPERATION_FAILED, e.getMessage(), e);
                done.run();
            }
        }
    }

    /**
     * One read-modify-write attempt.
     *
     * <p>The search only locates the policy's document id. Its source and sequence number are then
     * read with a realtime get, so that a retry sees the write that beat it even before the index is
     * refreshed.
     *
     * @param mutator changes the list in place and returns whether it changed anything; when it did
     *     not, nothing is written.
     */
    private static void update(
            Client client,
            Target target,
            Predicate<ArrayNode> mutator,
            int attempt,
            ActionListener<Void> listener) {
        SearchRequest search =
                new SearchRequest(Constants.INDEX_POLICIES)
                        .source(
                                new SearchSourceBuilder()
                                        .query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, target.spaceName()))
                                        .fetchSource(false)
                                        .size(1));

        client.search(
                search,
                ActionListener.wrap(
                        searchResponse -> {
                            SearchHit[] hits = searchResponse.getHits().getHits();
                            if (hits.length == 0) {
                                listener.onFailure(new IllegalStateException(target.missingPolicyMessage()));
                                return;
                            }
                            client.get(
                                    new GetRequest(Constants.INDEX_POLICIES, hits[0].getId()),
                                    ActionListener.wrap(
                                            policy -> write(client, target, mutator, attempt, policy, listener),
                                            listener::onFailure));
                        },
                        listener::onFailure));
    }

    private static void write(
            Client client,
            Target target,
            Predicate<ArrayNode> mutator,
            int attempt,
            GetResponse policy,
            ActionListener<Void> listener)
            throws Exception {
        if (!policy.isExists()) {
            // Deleted between the search and the get, e.g. by a space reset.
            listener.onFailure(new IllegalStateException(target.missingPolicyMessage()));
            return;
        }

        ObjectNode wrapper = (ObjectNode) MAPPER.readTree(policy.getSourceAsString());
        ObjectNode document = (ObjectNode) wrapper.get(Constants.KEY_DOCUMENT);
        JsonNode current = document.get(target.listKey());
        ArrayNode ids =
                current instanceof ArrayNode array ? array : document.putArray(target.listKey());

        if (!mutator.test(ids)) {
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
                            if (conflict && attempt < Constants.POLICY_LINKS_MAX_UPDATE_ATTEMPTS) {
                                TimeValue delay = backoff(attempt);
                                log.debug(
                                        Constants.D_LOG_POLICY_LINKS_CONFLICT,
                                        target.spaceName(),
                                        target.listKey(),
                                        attempt,
                                        delay);
                                client
                                        .threadPool()
                                        .schedule(
                                                () -> update(client, target, mutator, attempt + 1, listener),
                                                delay,
                                                ThreadPool.Names.GENERIC);
                                return;
                            }
                            if (conflict) {
                                // Out of attempts. The conflict is deliberately not chained as the
                                // cause: the transport actions would classify it as a 409 carrying
                                // OpenSearch's raw message (policy document id, sequence numbers).
                                // Reported like any other link failure instead, as a generic 500.
                                log.warn(
                                        Constants.W_LOG_POLICY_LINKS_RETRIES_EXHAUSTED,
                                        target.spaceName(),
                                        target.listKey(),
                                        attempt,
                                        e.getMessage());
                                listener.onFailure(
                                        new IllegalStateException(
                                                String.format(
                                                        Locale.ROOT,
                                                        Constants.E_500_POLICY_LINKS_RETRIES_EXHAUSTED,
                                                        target.listKey(),
                                                        target.spaceName(),
                                                        attempt)));
                                return;
                            }
                            listener.onFailure(e);
                        }));
    }

    /**
     * Full-jitter exponential backoff: a random delay up to {@code base * 2^(attempt - 1)}, capped.
     * The randomness keeps writers that conflicted together from retrying in lockstep.
     */
    static TimeValue backoff(int attempt) {
        long ceiling =
                Math.min(
                        Constants.POLICY_LINKS_RETRY_MAX_DELAY_MS,
                        Constants.POLICY_LINKS_RETRY_BASE_DELAY_MS << Math.min(attempt - 1, 20));
        return TimeValue.timeValueMillis(1 + Randomness.get().nextInt((int) ceiling));
    }
}
