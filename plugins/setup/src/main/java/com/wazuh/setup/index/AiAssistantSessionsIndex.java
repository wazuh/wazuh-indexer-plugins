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

import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.support.IndicesOptions;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.SearchHit;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Privileged access to the {@code wazuh-ai-assistant-sessions} data stream, reachable only through
 * the {@code plugin:wazuh/ai_assistant/session/write} gated transport action.
 *
 * <p>Every method takes the owner explicitly and every lookup filters on it, so a caller can only
 * ever reach its own documents. The owner is derived from the thread context by the transport
 * action ({@link com.wazuh.setup.utils.AuthenticatedUser}), never from the request body — that is
 * the whole point of routing these writes through a plugin instead of granting index {@code write}
 * on the stream.
 */
public class AiAssistantSessionsIndex {

    /** Data stream holding the AI assistant's chat sessions. */
    public static final String INDEX_NAME = "wazuh-ai-assistant-sessions";

    /** Document field holding the session's owner. Server-derived, never client input. */
    public static final String USER_FIELD = "user";

    /** Document field holding the session's title. */
    public static final String TITLE_FIELD = "title";

    /** Document field holding the opaque, unindexed transcript. */
    public static final String MESSAGES_FIELD = "messages";

    /** Document field holding the creation instant. Stamped once, then carried over. */
    public static final String CREATED_AT_FIELD = "created_at";

    /** Document field holding the last-activity instant. Re-stamped by create and replace. */
    public static final String UPDATED_AT_FIELD = "updated_at";

    /**
     * The data stream's timestamp field. Always equal to {@link #CREATED_AT_FIELD} and not exposed by
     * the API — it exists only because a data stream requires one.
     */
    public static final String TIMESTAMP_FIELD = "@timestamp";

    /**
     * Sessions one owner may hold. Enforced on create only: an update adds no document, so it must
     * keep working at the cap. Matches the Dashboard's {@code MAX_CONVERSATIONS_PER_OWNER}.
     */
    public static final int MAX_SESSIONS_PER_USER = 500;

    /** Shape of the opaque {@code version} token: {@code "<seq_no>:<primary_term>"}. */
    private static final Pattern VERSION_TOKEN = Pattern.compile("^(\\d+):(\\d+)$");

    private final Client client;
    private final ThreadPool threadPool;

    /**
     * Constructor.
     *
     * @param client OpenSearch client.
     * @param threadPool node thread pool, used to stash the calling user's security context.
     */
    public AiAssistantSessionsIndex(Client client, ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
    }

    /**
     * One stored session plus the bookkeeping a later write needs: the concrete backing index holding
     * it and the optimistic-concurrency pair read alongside it.
     */
    public static class SessionHit {
        private final String id;
        private final String index;
        private final long seqNo;
        private final long primaryTerm;
        private final Map<String, Object> source;

        /**
         * Constructor. Public so tests can build a stored session without going near reflection.
         *
         * @param id the session document id.
         * @param index the concrete backing index holding it.
         * @param seqNo the sequence number read alongside the document.
         * @param primaryTerm the primary term read alongside the document.
         * @param source the document source.
         */
        public SessionHit(
                String id, String index, long seqNo, long primaryTerm, Map<String, Object> source) {
            this.id = id;
            this.index = index;
            this.seqNo = seqNo;
            this.primaryTerm = primaryTerm;
            this.source = source;
        }

        public String getId() {
            return this.id;
        }

        /**
         * @return the concrete backing index, e.g. {@code .ds-wazuh-ai-assistant-sessions-000002}.
         */
        public String getIndex() {
            return this.index;
        }

        public long getSeqNo() {
            return this.seqNo;
        }

        public long getPrimaryTerm() {
            return this.primaryTerm;
        }

        public Map<String, Object> getSource() {
            return this.source;
        }
    }

    /** The outcome of a write: the document's id and the version token to hand back to the client. */
    public static class SessionWrite {
        private final String id;
        private final String version;

        /**
         * Constructor. Public for the same reason {@link SessionHit#SessionHit} is.
         *
         * @param id the session document id.
         * @param version the opaque version token the write produced.
         */
        public SessionWrite(String id, String version) {
            this.id = id;
            this.version = version;
        }

        public String getId() {
            return this.id;
        }

        public String getVersion() {
            return this.version;
        }
    }

    /**
     * Counts the sessions owned by the given user, for the create-path cap.
     *
     * @param user the owner to count for.
     * @param listener receives the count.
     */
    public void countForUser(String user, ActionListener<Long> listener) {
        SearchSourceBuilder source =
                new SearchSourceBuilder()
                        .query(QueryBuilders.termQuery(USER_FIELD, user))
                        .size(0)
                        .trackTotalHits(true);
        SearchRequest request = search(source);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.search(
                    request,
                    ActionListener.wrap(
                            response -> listener.onResponse(response.getHits().getTotalHits().value()),
                            listener::onFailure));
        }
    }

    /**
     * Appends a new session document, owned by {@code user}.
     *
     * <p>Written against the data stream <em>name</em> with {@code op_type=create} and no explicit
     * id: a data stream's alias accepts appends only, and that combination is what makes OpenSearch
     * mint the id. No backing-index resolution is needed on this path.
     *
     * @param source the full document to store, {@code user}/{@code created_at}/{@code
     *     updated_at}/{@code @timestamp} already stamped by the caller.
     * @param listener receives the new id and its version token.
     */
    public void create(Map<String, Object> source, ActionListener<SessionWrite> listener) {
        IndexRequest request =
                new IndexRequest(INDEX_NAME)
                        .create(true)
                        .source(source, XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.index(
                    request,
                    ActionListener.wrap(
                            response -> listener.onResponse(toWrite(response)), listener::onFailure));
        }
    }

    /**
     * Resolves one session by id, owned by {@code user}.
     *
     * <p>A plain get-by-id cannot be used: this is a data stream whose backing index rolls over
     * daily, and the get API targets exactly one concrete index with no way to know which one holds a
     * given id. A search on the stream fans out across every backing index and reports the one that
     * has it, and {@code seq_no_primary_term} makes the same round trip yield the pair the following
     * write must carry.
     *
     * <p>The owner is part of the query, so a session belonging to somebody else simply returns no
     * hit. The {@code 404} the caller sees therefore falls out of the lookup rather than being a
     * separate branch — and it is a {@code 404} rather than a {@code 403} deliberately, because a
     * {@code 403} would confirm that another user's session id exists.
     *
     * @param user the owner the session must belong to.
     * @param id the session id.
     * @param listener receives the hit, or {@code null} when there is none.
     */
    public void findHit(String user, String id, ActionListener<SessionHit> listener) {
        SearchSourceBuilder source =
                new SearchSourceBuilder()
                        .query(
                                QueryBuilders.boolQuery()
                                        .filter(QueryBuilders.idsQuery().addIds(id))
                                        .filter(QueryBuilders.termQuery(USER_FIELD, user)))
                        .seqNoAndPrimaryTerm(true)
                        .size(1);
        SearchRequest request = search(source);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.search(
                    request,
                    ActionListener.wrap(
                            response -> listener.onResponse(toHit(response)), listener::onFailure));
        }
    }

    /**
     * Replaces an already-resolved session document wholesale.
     *
     * <p>Targets {@code hit.getIndex()} — the concrete backing index — never the stream name, which
     * accepts appends only. A document never moves between backing indices, so a hit resolved earlier
     * in the same request is still valid to write against.
     *
     * <p>Deliberately a full replace rather than the partial {@code _update} API, which the security
     * plugin refuses outright for any role document-level security applies to ({@code
     * security_exception: Update is not supported when FLS or DLS or Fieldmasking is activated}). The
     * caller therefore has to pass the whole document, carrying over whatever the request is not
     * changing.
     *
     * <p>The optimistic-concurrency pair is required, not optional: a backing index rejects an
     * unconditional {@code op_type=index} write outright ({@code illegal_argument_exception: index
     * request with op_type=index and no if_primary_term and if_seq_no set targeting backing indices
     * is disallowed}). There is no overwrite-regardless fallback to reach for.
     *
     * @param hit the resolved session being replaced.
     * @param source the full document to store.
     * @param ifSeqNo sequence number the stored document must still be at.
     * @param ifPrimaryTerm primary term the stored document must still be at.
     * @param listener receives the id and the write's own fresh version token; fails with a version
     *     conflict when the stored document has moved past the pair.
     */
    public void replace(
            SessionHit hit,
            Map<String, Object> source,
            long ifSeqNo,
            long ifPrimaryTerm,
            ActionListener<SessionWrite> listener) {
        IndexRequest request =
                new IndexRequest(hit.getIndex())
                        .id(hit.getId())
                        .setIfSeqNo(ifSeqNo)
                        .setIfPrimaryTerm(ifPrimaryTerm)
                        .source(source, XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.index(
                    request,
                    ActionListener.wrap(
                            response -> listener.onResponse(toWrite(response)), listener::onFailure));
        }
    }

    /**
     * Deletes an already-resolved session document, against its backing index for the same reason
     * {@link #replace} does.
     *
     * @param hit the resolved session to delete.
     * @param listener receives the session id on success.
     */
    public void delete(SessionHit hit, ActionListener<String> listener) {
        DeleteRequest request =
                new DeleteRequest(hit.getIndex(), hit.getId())
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.WAIT_UNTIL);

        try (ThreadContext.StoredContext ignored = this.stashContext()) {
            this.client.delete(
                    request,
                    ActionListener.wrap(response -> listener.onResponse(hit.getId()), listener::onFailure));
        }
    }

    /**
     * Encodes an optimistic-concurrency pair as the opaque {@code version} token clients round-trip.
     * OpenSearch has no single row version, hence the pair.
     *
     * @param seqNo the sequence number.
     * @param primaryTerm the primary term.
     * @return the token, {@code "<seq_no>:<primary_term>"}.
     */
    public static String encodeVersion(long seqNo, long primaryTerm) {
        return seqNo + ":" + primaryTerm;
    }

    /**
     * Inverse of {@link #encodeVersion}.
     *
     * @param token the client-supplied token.
     * @return {@code {seqNo, primaryTerm}}, or {@code null} for anything that is not exactly that
     *     shape. An undecodable token is treated as absent rather than rejected, matching the token's
     *     "opaque, never validated beyond round-tripping" contract.
     */
    public static long[] decodeVersion(String token) {
        if (token == null) {
            return null;
        }
        Matcher matcher = VERSION_TOKEN.matcher(token);
        if (!matcher.matches()) {
            return null;
        }
        try {
            return new long[] {Long.parseLong(matcher.group(1)), Long.parseLong(matcher.group(2))};
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /**
     * Builds a search against the sessions data stream.
     *
     * <p>Lenient on a missing index on purpose. The stream is created by this plugin at bootstrap,
     * but a request can arrive before that has happened — or after an operator has deleted it — and
     * an {@code index_not_found_exception} surfacing from a lookup would turn "no such session" into
     * a confusing {@code 404} about an index. With lenient options the lookup simply finds nothing,
     * which is the same answer, phrased in terms of the resource the caller asked for.
     */
    private static SearchRequest search(SearchSourceBuilder source) {
        return new SearchRequest(INDEX_NAME)
                .indicesOptions(IndicesOptions.LENIENT_EXPAND_OPEN)
                .source(source);
    }

    private static SessionWrite toWrite(IndexResponse response) {
        return new SessionWrite(
                response.getId(), encodeVersion(response.getSeqNo(), response.getPrimaryTerm()));
    }

    private static SessionHit toHit(SearchResponse response) {
        SearchHit[] hits = response.getHits().getHits();
        if (hits.length == 0) {
            return null;
        }
        SearchHit hit = hits[0];
        return new SessionHit(
                hit.getId(), hit.getIndex(), hit.getSeqNo(), hit.getPrimaryTerm(), hit.getSourceAsMap());
    }

    /**
     * Stashes the calling user's security context so the subsequent client call runs with this
     * plugin's own privileges instead of the caller's. The owner has already been resolved from the
     * context by the transport action, and every query here filters on it, so the elevated call can
     * still only reach that user's documents.
     *
     * @return the stored context, auto-restored on close.
     */
    private ThreadContext.StoredContext stashContext() {
        return this.threadPool.getThreadContext().stashContext();
    }
}
