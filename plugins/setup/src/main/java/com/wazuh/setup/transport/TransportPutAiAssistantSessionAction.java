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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.OpenSearchException;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;

import java.time.Instant;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.action.PutAiAssistantSessionAction;
import com.wazuh.setup.action.PutAiAssistantSessionRequest;
import com.wazuh.setup.action.PutAiAssistantSessionResponse;
import com.wazuh.setup.index.AiAssistantSessionsIndex;
import com.wazuh.setup.index.AiAssistantSessionsIndex.SessionHit;
import com.wazuh.setup.index.AiAssistantSessionsIndex.SessionWrite;
import com.wazuh.setup.utils.AuthenticatedUser;

/**
 * Transport action that performs every write to the caller's own AI assistant sessions. Gated by
 * {@link PutAiAssistantSessionAction#NAME} as a cluster permission.
 *
 * <p>This class is the fix for the authorization gap this API exists to close. Document-level
 * security is a read-path filter and cannot scope a write, so the {@code user} field on a session —
 * the field the read filter keys on — was forgeable by any account able to reach the index. Here
 * {@code user} is resolved from the security plugin's thread context and stamped onto the document,
 * and whatever the caller sent for it is dropped. Update, rename and delete load the stored
 * document first, through a lookup that filters on the same resolved owner, so a session belonging
 * to someone else is simply not found.
 */
public class TransportPutAiAssistantSessionAction
        extends HandledTransportAction<PutAiAssistantSessionRequest, PutAiAssistantSessionResponse> {
    private static final Logger log =
            LogManager.getLogger(TransportPutAiAssistantSessionAction.class);
    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Longest title accepted. Matches the Dashboard's {@code CONVERSATION_MAX_TITLE_LENGTH}. */
    private static final int MAX_TITLE_LENGTH = 200;

    /**
     * Most messages one session may hold. Matches the Dashboard's {@code CONVERSATION_MAX_MESSAGES}.
     */
    private static final int MAX_MESSAGES = 1000;

    private static final String TITLE_KEY = "title";
    private static final String MESSAGES_KEY = "messages";
    private static final String EXPECTED_VERSION_KEY = "expected_version";
    private static final String ID_KEY = "id";
    private static final String VERSION_KEY = "version";

    private static final String INVALID_BODY = "Invalid request body.";
    private static final String TITLE_REQUIRED = "Session title is required.";
    private static final String TITLE_TOO_LONG =
            "Session title must be " + MAX_TITLE_LENGTH + " characters or fewer.";
    private static final String MESSAGES_REQUIRED = "Session messages are required.";
    private static final String TOO_MANY_MESSAGES =
            "A session cannot hold more than " + MAX_MESSAGES + " messages.";
    private static final String CAP_REACHED =
            "You have reached the maximum of "
                    + AiAssistantSessionsIndex.MAX_SESSIONS_PER_USER
                    + " saved sessions.";
    private static final String VERSION_CONFLICT =
            "Session was updated by another session since you last loaded it. Refresh and retry.";
    private static final String SESSION_DELETED = "Session deleted.";
    private static final String NOT_FOUND_PREFIX = "Session not found: ";

    private final AiAssistantSessionsIndex sessionsIndex;
    private final ThreadPool threadPool;

    /**
     * Constructor.
     *
     * @param transportService the transport service.
     * @param actionFilters the action filters.
     * @param sessionsIndex privileged accessor for the sessions data stream.
     * @param threadPool node thread pool; its thread context carries the authenticated caller.
     */
    @Inject
    public TransportPutAiAssistantSessionAction(
            TransportService transportService,
            ActionFilters actionFilters,
            AiAssistantSessionsIndex sessionsIndex,
            ThreadPool threadPool) {
        super(
                PutAiAssistantSessionAction.NAME,
                transportService,
                actionFilters,
                PutAiAssistantSessionRequest::new);
        this.sessionsIndex = sessionsIndex;
        this.threadPool = threadPool;
    }

    @Override
    protected void doExecute(
            Task task,
            PutAiAssistantSessionRequest request,
            ActionListener<PutAiAssistantSessionResponse> listener) {
        // Resolved here, before any client call stashes the context: a stashed context no longer
        // carries the security plugin's transient. This value, not the request body, is the owner.
        final String user = AuthenticatedUser.resolve(this.threadPool.getThreadContext());

        switch (request.getOperation()) {
            case CREATE:
                this.create(user, request, listener);
                break;
            case UPDATE:
                this.update(user, request, listener);
                break;
            case RENAME:
                this.rename(user, request, listener);
                break;
            case DELETE:
                this.delete(user, request, listener);
                break;
        }
    }

    // ---------------------------------------------------------------------------------------------
    // CREATE
    // ---------------------------------------------------------------------------------------------

    private void create(
            String user,
            PutAiAssistantSessionRequest request,
            ActionListener<PutAiAssistantSessionResponse> listener) {
        Map<String, Object> body;
        try {
            body = parseBody(request.getPayload());
        } catch (Exception e) {
            listener.onResponse(badRequest(INVALID_BODY));
            return;
        }

        String title = readTitle(body);
        if (title == null) {
            listener.onResponse(badRequest(TITLE_REQUIRED));
            return;
        }
        if (title.length() > MAX_TITLE_LENGTH) {
            listener.onResponse(badRequest(TITLE_TOO_LONG));
            return;
        }
        if (!body.containsKey(MESSAGES_KEY) || !(body.get(MESSAGES_KEY) instanceof List)) {
            listener.onResponse(badRequest(MESSAGES_REQUIRED));
            return;
        }
        List<?> messages = (List<?>) body.get(MESSAGES_KEY);
        if (messages.size() > MAX_MESSAGES) {
            listener.onResponse(badRequest(TOO_MANY_MESSAGES));
            return;
        }

        this.sessionsIndex.countForUser(
                user,
                ActionListener.wrap(
                        count -> {
                            if (count >= AiAssistantSessionsIndex.MAX_SESSIONS_PER_USER) {
                                // 409, not 400: the request is well formed, it is the stored state that
                                // blocks it. The cap is never applied to an update, which adds no document.
                                listener.onResponse(
                                        PutAiAssistantSessionResponse.envelope(CAP_REACHED, RestStatus.CONFLICT, null));
                                return;
                            }

                            String now = Instant.now().toString();
                            Map<String, Object> source = new LinkedHashMap<>();
                            // Every field below is server-owned. Whatever the caller sent for `user`,
                            // `created_at`, `updated_at` or `@timestamp` never reaches this map, and keys
                            // outside the allowlist are dropped rather than rejected so that a client may
                            // POST back a document it previously read without a 400.
                            source.put(AiAssistantSessionsIndex.USER_FIELD, user);
                            source.put(AiAssistantSessionsIndex.TITLE_FIELD, title);
                            source.put(AiAssistantSessionsIndex.MESSAGES_FIELD, messages);
                            source.put(AiAssistantSessionsIndex.CREATED_AT_FIELD, now);
                            source.put(AiAssistantSessionsIndex.UPDATED_AT_FIELD, now);
                            source.put(AiAssistantSessionsIndex.TIMESTAMP_FIELD, now);

                            this.sessionsIndex.create(
                                    source,
                                    ActionListener.wrap(
                                            write ->
                                                    listener.onResponse(session(write.getId(), source, write.getVersion())),
                                            e -> {
                                                log.error("Failed to create AI assistant session: {}", e.getMessage(), e);
                                                listener.onFailure(e);
                                            }));
                        },
                        e -> {
                            log.error("Failed to count AI assistant sessions: {}", e.getMessage(), e);
                            listener.onFailure(e);
                        }));
    }

    // ---------------------------------------------------------------------------------------------
    // UPDATE
    // ---------------------------------------------------------------------------------------------

    private void update(
            String user,
            PutAiAssistantSessionRequest request,
            ActionListener<PutAiAssistantSessionResponse> listener) {
        Map<String, Object> body;
        try {
            body = parseBody(request.getPayload());
        } catch (Exception e) {
            listener.onResponse(badRequest(INVALID_BODY));
            return;
        }

        if (!body.containsKey(MESSAGES_KEY) || !(body.get(MESSAGES_KEY) instanceof List)) {
            listener.onResponse(badRequest(MESSAGES_REQUIRED));
            return;
        }
        List<?> messages = (List<?>) body.get(MESSAGES_KEY);
        if (messages.size() > MAX_MESSAGES) {
            listener.onResponse(badRequest(TOO_MANY_MESSAGES));
            return;
        }

        // `title` is optional here on purpose. A chat client auto-saves every turn; if each save
        // resent a recomputed title it would silently revert a rename the user had just made. Absent
        // means "keep the stored title" — but a title that is present and blank is still a 400.
        final String title;
        if (body.containsKey(TITLE_KEY)) {
            title = readTitle(body);
            if (title == null) {
                listener.onResponse(badRequest(TITLE_REQUIRED));
                return;
            }
            if (title.length() > MAX_TITLE_LENGTH) {
                listener.onResponse(badRequest(TITLE_TOO_LONG));
                return;
            }
        } else {
            title = null;
        }

        final String sessionId = request.getSessionId();
        final long[] expected =
                AiAssistantSessionsIndex.decodeVersion(readString(body, EXPECTED_VERSION_KEY));

        this.sessionsIndex.findHit(
                user,
                sessionId,
                ActionListener.wrap(
                        hit -> {
                            if (hit == null) {
                                listener.onFailure(new ResourceNotFoundException(NOT_FOUND_PREFIX + sessionId));
                                return;
                            }
                            Map<String, Object> stored = hit.getSource();
                            Map<String, Object> source = new LinkedHashMap<>();
                            // The owner is carried over from the STORED document, never re-derived and
                            // never taken from the body: the lookup above already proved it equals the
                            // authenticated caller.
                            source.put(
                                    AiAssistantSessionsIndex.USER_FIELD,
                                    stored.get(AiAssistantSessionsIndex.USER_FIELD));
                            source.put(
                                    AiAssistantSessionsIndex.TITLE_FIELD,
                                    title != null ? title : stored.get(AiAssistantSessionsIndex.TITLE_FIELD));
                            source.put(AiAssistantSessionsIndex.MESSAGES_FIELD, messages);
                            source.put(
                                    AiAssistantSessionsIndex.CREATED_AT_FIELD,
                                    stored.get(AiAssistantSessionsIndex.CREATED_AT_FIELD));
                            source.put(AiAssistantSessionsIndex.UPDATED_AT_FIELD, Instant.now().toString());
                            source.put(
                                    AiAssistantSessionsIndex.TIMESTAMP_FIELD,
                                    stored.get(AiAssistantSessionsIndex.TIMESTAMP_FIELD));

                            // Either pair satisfies the platform's requirement that a backing-index write
                            // carry one; they differ only in how wide the check is. The caller's
                            // `expected_version` catches a write made since the CALLER's last read; the
                            // pair just read catches one made since this request started.
                            long ifSeqNo = expected != null ? expected[0] : hit.getSeqNo();
                            long ifPrimaryTerm = expected != null ? expected[1] : hit.getPrimaryTerm();

                            this.replaceThen(
                                    hit,
                                    source,
                                    ifSeqNo,
                                    ifPrimaryTerm,
                                    listener,
                                    write -> session(hit.getId(), source, write.getVersion()));
                        },
                        e -> {
                            log.error("Failed to look up AI assistant session: {}", e.getMessage(), e);
                            listener.onFailure(e);
                        }));
    }

    // ---------------------------------------------------------------------------------------------
    // RENAME
    // ---------------------------------------------------------------------------------------------

    private void rename(
            String user,
            PutAiAssistantSessionRequest request,
            ActionListener<PutAiAssistantSessionResponse> listener) {
        Map<String, Object> body;
        try {
            body = parseBody(request.getPayload());
        } catch (Exception e) {
            listener.onResponse(badRequest(INVALID_BODY));
            return;
        }

        String title = readTitle(body);
        if (title == null) {
            listener.onResponse(badRequest(TITLE_REQUIRED));
            return;
        }
        if (title.length() > MAX_TITLE_LENGTH) {
            listener.onResponse(badRequest(TITLE_TOO_LONG));
            return;
        }

        final String sessionId = request.getSessionId();
        final String newTitle = title;

        this.sessionsIndex.findHit(
                user,
                sessionId,
                ActionListener.wrap(
                        hit -> {
                            if (hit == null) {
                                listener.onFailure(new ResourceNotFoundException(NOT_FOUND_PREFIX + sessionId));
                                return;
                            }
                            Map<String, Object> source = new LinkedHashMap<>(hit.getSource());
                            source.put(AiAssistantSessionsIndex.TITLE_FIELD, newTitle);
                            // `updated_at` is deliberately NOT re-stamped. A rename is not session
                            // activity; bumping it would jump the row to the top of a list ordered by
                            // last activity and misreport when the session was last used.

                            this.replaceThen(
                                    hit,
                                    source,
                                    hit.getSeqNo(),
                                    hit.getPrimaryTerm(),
                                    listener,
                                    write -> {
                                        Map<String, Object> renamed = new LinkedHashMap<>();
                                        renamed.put(ID_KEY, hit.getId());
                                        renamed.put(AiAssistantSessionsIndex.TITLE_FIELD, newTitle);
                                        renamed.put(
                                                AiAssistantSessionsIndex.UPDATED_AT_FIELD,
                                                source.get(AiAssistantSessionsIndex.UPDATED_AT_FIELD));
                                        renamed.put(VERSION_KEY, write.getVersion());
                                        return new PutAiAssistantSessionResponse(RestStatus.OK, renamed);
                                    });
                        },
                        e -> {
                            log.error("Failed to look up AI assistant session: {}", e.getMessage(), e);
                            listener.onFailure(e);
                        }));
    }

    // ---------------------------------------------------------------------------------------------
    // DELETE
    // ---------------------------------------------------------------------------------------------

    private void delete(
            String user,
            PutAiAssistantSessionRequest request,
            ActionListener<PutAiAssistantSessionResponse> listener) {
        final String sessionId = request.getSessionId();
        this.sessionsIndex.findHit(
                user,
                sessionId,
                ActionListener.wrap(
                        hit -> {
                            if (hit == null) {
                                listener.onFailure(new ResourceNotFoundException(NOT_FOUND_PREFIX + sessionId));
                                return;
                            }
                            this.sessionsIndex.delete(
                                    hit,
                                    ActionListener.wrap(
                                            id ->
                                                    listener.onResponse(
                                                            PutAiAssistantSessionResponse.envelope(
                                                                    SESSION_DELETED, RestStatus.OK, id)),
                                            e -> {
                                                log.error("Failed to delete AI assistant session: {}", e.getMessage(), e);
                                                listener.onFailure(e);
                                            }));
                        },
                        e -> {
                            log.error("Failed to look up AI assistant session: {}", e.getMessage(), e);
                            listener.onFailure(e);
                        }));
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    /** A write's outcome, mapped to the response body that route returns. */
    private interface WriteRenderer {
        PutAiAssistantSessionResponse render(SessionWrite write);
    }

    /**
     * Runs a replace and renders its outcome, translating a version conflict into the documented
     * {@code 409}.
     *
     * <p>A conflict is never retried with a freshly read pair: retrying is exactly the silent
     * overwrite {@code expected_version} exists to prevent. The {@code 409} is surfaced and the
     * client re-reads, merges and decides.
     */
    private void replaceThen(
            SessionHit hit,
            Map<String, Object> source,
            long ifSeqNo,
            long ifPrimaryTerm,
            ActionListener<PutAiAssistantSessionResponse> listener,
            WriteRenderer renderer) {
        this.sessionsIndex.replace(
                hit,
                source,
                ifSeqNo,
                ifPrimaryTerm,
                ActionListener.wrap(
                        write -> listener.onResponse(renderer.render(write)),
                        e -> {
                            if (isVersionConflict(e)) {
                                listener.onResponse(
                                        PutAiAssistantSessionResponse.envelope(
                                                VERSION_CONFLICT, RestStatus.CONFLICT, null));
                                return;
                            }
                            log.error("Failed to write AI assistant session: {}", e.getMessage(), e);
                            listener.onFailure(e);
                        }));
    }

    private static boolean isVersionConflict(Exception e) {
        return e instanceof OpenSearchException
                && ((OpenSearchException) e).status() == RestStatus.CONFLICT;
    }

    /**
     * Renders the full session, the shape {@code POST} and {@code PUT} return. {@code @timestamp} is
     * not exposed: it exists only for the data stream's own bookkeeping and always equals {@code
     * created_at}.
     */
    private static PutAiAssistantSessionResponse session(
            String id, Map<String, Object> source, String version) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put(ID_KEY, id);
        body.put(
                AiAssistantSessionsIndex.TITLE_FIELD, source.get(AiAssistantSessionsIndex.TITLE_FIELD));
        body.put(
                AiAssistantSessionsIndex.CREATED_AT_FIELD,
                source.get(AiAssistantSessionsIndex.CREATED_AT_FIELD));
        body.put(
                AiAssistantSessionsIndex.UPDATED_AT_FIELD,
                source.get(AiAssistantSessionsIndex.UPDATED_AT_FIELD));
        body.put(
                AiAssistantSessionsIndex.MESSAGES_FIELD,
                source.get(AiAssistantSessionsIndex.MESSAGES_FIELD));
        body.put(VERSION_KEY, version);
        return new PutAiAssistantSessionResponse(RestStatus.OK, body);
    }

    private static PutAiAssistantSessionResponse badRequest(String message) {
        return PutAiAssistantSessionResponse.envelope(message, RestStatus.BAD_REQUEST, null);
    }

    /**
     * Reads and trims {@code title}.
     *
     * @return the trimmed title, or {@code null} when the key is missing, not a string, or blank
     *     after trimming.
     */
    private static String readTitle(Map<String, Object> body) {
        String title = readString(body, TITLE_KEY);
        if (title == null) {
            return null;
        }
        String trimmed = title.trim();
        return trimmed.isEmpty() ? null : trimmed;
    }

    private static String readString(Map<String, Object> body, String key) {
        Object value = body.get(key);
        return value instanceof String ? (String) value : null;
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> parseBody(String payload) throws Exception {
        JsonNode root = MAPPER.readTree(payload);
        if (root == null || !root.isObject()) {
            throw new IllegalArgumentException("request body must be a JSON object");
        }
        return MAPPER.convertValue(root, Map.class);
    }
}
