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

import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.index.shard.ShardId;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.engine.VersionConflictEngineException;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.TransportService;
import org.junit.After;
import org.junit.Before;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.action.PutAiAssistantSessionRequest;
import com.wazuh.setup.action.PutAiAssistantSessionRequest.Operation;
import com.wazuh.setup.action.PutAiAssistantSessionResponse;
import com.wazuh.setup.index.AiAssistantSessionsIndex;
import com.wazuh.setup.index.AiAssistantSessionsIndex.SessionHit;
import com.wazuh.setup.index.AiAssistantSessionsIndex.SessionWrite;
import com.wazuh.setup.utils.AuthenticatedUser;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TransportPutAiAssistantSessionAction}, which is where the fix for
 * internal-devel-requests#6111 lives: the session's {@code user} field is stamped from the
 * authenticated caller and never read from the request body.
 *
 * <p>These tests capture the document handed to the index accessor, so they assert on exactly what
 * would be written. The impersonation refusal itself needs a second identity and therefore a
 * security-enabled cluster, which {@code integTest} does not provide — see {@code
 * AiAssistantSessionsIT}'s class Javadoc for that split.
 */
public class TransportPutAiAssistantSessionActionTests extends OpenSearchTestCase {

    private static final String CALLER = "qadls-probe";
    private static final String SESSION_ID = "8itvhqABtpJqXy3PWi31";
    private static final String BACKING_INDEX = ".ds-wazuh-ai-assistant-sessions-000002";

    private TransportPutAiAssistantSessionAction action;
    private AutoCloseable mocks;
    private ThreadContext threadContext;

    @Mock private AiAssistantSessionsIndex sessionsIndex;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mocks = MockitoAnnotations.openMocks(this);

        this.threadContext = new ThreadContext(Settings.EMPTY);
        this.threadContext.putTransient(
                AuthenticatedUser.USER_INFO_TRANSIENT, CALLER + "|backend|own_index|");

        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(this.threadContext);

        this.action =
                new TransportPutAiAssistantSessionAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        this.sessionsIndex,
                        threadPool);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        if (this.mocks != null) {
            this.mocks.close();
        }
    }

    // ---------------------------------------------------------------------------------------------
    // CREATE — the stamping half of the fix
    // ---------------------------------------------------------------------------------------------

    public void testCreateStampsTheCallerAndDiscardsAForgedOwner() {
        mockCount(0);
        mockCreate("newid", "3:1");

        PutAiAssistantSessionResponse response =
                execute(
                        Operation.CREATE,
                        null,
                        "{\"title\":\"forged\",\"messages\":[],\"user\":\"admin\","
                                + "\"created_at\":\"2000-01-01T00:00:00Z\","
                                + "\"updated_at\":\"2000-01-01T00:00:00Z\","
                                + "\"@timestamp\":\"2000-01-01T00:00:00Z\",\"junk\":\"dropped\"}");

        assertEquals(RestStatus.OK, response.getStatus());
        Map<String, Object> written = capturedCreate();

        // The whole point of the endpoint: `user` is the authenticated caller, not "admin".
        assertEquals(CALLER, written.get(AiAssistantSessionsIndex.USER_FIELD));
        assertNotEquals("2000-01-01T00:00:00Z", written.get(AiAssistantSessionsIndex.CREATED_AT_FIELD));
        assertNotEquals("2000-01-01T00:00:00Z", written.get(AiAssistantSessionsIndex.UPDATED_AT_FIELD));
        assertNotEquals("2000-01-01T00:00:00Z", written.get(AiAssistantSessionsIndex.TIMESTAMP_FIELD));
        // Unknown keys are dropped rather than rejected, so a round-tripped document does not 400.
        assertFalse(written.containsKey("junk"));

        // @timestamp exists only for the data stream's bookkeeping and always equals created_at.
        assertEquals(
                written.get(AiAssistantSessionsIndex.CREATED_AT_FIELD),
                written.get(AiAssistantSessionsIndex.TIMESTAMP_FIELD));
        assertEquals(
                written.get(AiAssistantSessionsIndex.CREATED_AT_FIELD),
                written.get(AiAssistantSessionsIndex.UPDATED_AT_FIELD));

        // ... and it is not exposed in the response, unlike created_at/updated_at.
        assertFalse(response.getBody().containsKey(AiAssistantSessionsIndex.TIMESTAMP_FIELD));
        assertEquals("newid", response.getBody().get("id"));
        assertEquals("3:1", response.getBody().get("version"));
    }

    public void testCreateTrimsTheTitle() {
        mockCount(0);
        mockCreate("newid", "3:1");
        execute(Operation.CREATE, null, "{\"title\":\"  spaced  \",\"messages\":[]}");
        assertEquals("spaced", capturedCreate().get(AiAssistantSessionsIndex.TITLE_FIELD));
    }

    public void testCreateRejectsABlankOrOverlongTitle() {
        assertBadRequest(
                execute(Operation.CREATE, null, "{\"title\":\"   \",\"messages\":[]}"),
                "Session title is required.");
        assertBadRequest(
                execute(Operation.CREATE, null, "{\"messages\":[]}"), "Session title is required.");
        assertBadRequest(
                execute(Operation.CREATE, null, "{\"title\":\"" + "x".repeat(201) + "\",\"messages\":[]}"),
                "Session title must be 200 characters or fewer.");
        verify(this.sessionsIndex, never()).create(any(), any());
    }

    public void testCreateRejectsAMissingOrOverlongTranscript() {
        assertBadRequest(
                execute(Operation.CREATE, null, "{\"title\":\"t\"}"), "Session messages are required.");
        assertBadRequest(
                execute(Operation.CREATE, null, "{\"title\":\"t\",\"messages\":\"nope\"}"),
                "Session messages are required.");
        assertBadRequest(
                execute(
                        Operation.CREATE,
                        null,
                        "{\"title\":\"t\",\"messages\":[" + "{},".repeat(1000) + "{}]}"),
                "A session cannot hold more than 1000 messages.");
        verify(this.sessionsIndex, never()).create(any(), any());
    }

    public void testRejectsAnOversizedPayloadBeforeParsingIt() {
        // MAX_MESSAGES bounds how many turns a session holds, not how large each one is. Without a
        // byte ceiling the only limit is http.max_content_length (100MB by default), which would
        // make the 500-session per-owner cap meaningless as a storage bound.
        String oversized =
                "{\"title\":\"t\",\"messages\":[{\"role\":\"user\",\"content\":\""
                        + "x".repeat(5 * 1024 * 1024)
                        + "\"}]}";

        for (Operation operation : List.of(Operation.CREATE, Operation.UPDATE, Operation.RENAME)) {
            assertBadRequest(
                    execute(operation, SESSION_ID, oversized), "Session payload must be 5 MiB or smaller.");
        }

        // Rejected before the body is parsed, so nothing reaches the index — not even the lookup
        // the update and rename paths would otherwise do first.
        verify(this.sessionsIndex, never()).create(any(), any());
        verify(this.sessionsIndex, never()).findHit(any(), any(), any());
        verify(this.sessionsIndex, never()).countForUser(any(), any());
    }

    public void testAcceptsAPayloadJustUnderTheLimit() {
        mockCount(0);
        mockCreate("newid", "3:1");

        // Padded to land a few hundred bytes short of the 5 MiB ceiling.
        String content = "x".repeat(5 * 1024 * 1024 - 512);
        String body =
                "{\"title\":\"t\",\"messages\":[{\"role\":\"user\",\"content\":\"" + content + "\"}]}";
        assertTrue(
                "the fixture must stay under the limit",
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length <= 5 * 1024 * 1024);

        assertEquals(RestStatus.OK, execute(Operation.CREATE, null, body).getStatus());
    }

    public void testPayloadSizeIsMeasuredInBytesNotCharacters() {
        // A multi-byte character must count for its encoded width, or the ceiling is bypassed by
        // sending non-ASCII: "€" is 3 bytes of UTF-8 but one char.
        String body =
                "{\"title\":\"t\",\"messages\":[{\"role\":\"user\",\"content\":\""
                        + "\u20ac".repeat(2 * 1024 * 1024)
                        + "\"}]}";
        assertTrue(
                "the fixture is under the limit by character count", body.length() < 5 * 1024 * 1024);
        assertTrue(
                "... but over it by byte count",
                body.getBytes(java.nio.charset.StandardCharsets.UTF_8).length > 5 * 1024 * 1024);

        assertBadRequest(
                execute(Operation.CREATE, null, body), "Session payload must be 5 MiB or smaller.");
        verify(this.sessionsIndex, never()).create(any(), any());
    }

    public void testCreateRejectsAMalformedBody() {
        assertBadRequest(execute(Operation.CREATE, null, "not json"), "Invalid request body.");
        assertBadRequest(execute(Operation.CREATE, null, "[1,2,3]"), "Invalid request body.");
    }

    public void testCreateAtTheCapIsAConflictNotABadRequest() {
        mockCount(AiAssistantSessionsIndex.MAX_SESSIONS_PER_USER);
        PutAiAssistantSessionResponse response =
                execute(Operation.CREATE, null, "{\"title\":\"t\",\"messages\":[]}");
        // 409, not 400: the request is well formed, it is the stored state that blocks it.
        assertEquals(RestStatus.CONFLICT, response.getStatus());
        assertEquals(
                "You have reached the maximum of 500 saved sessions.", response.getBody().get("message"));
        verify(this.sessionsIndex, never()).create(any(), any());
    }

    public void testCreateCountsForTheCallerOnly() {
        mockCount(0);
        mockCreate("newid", "3:1");
        execute(Operation.CREATE, null, "{\"title\":\"t\",\"messages\":[],\"user\":\"admin\"}");
        // The cap is per owner, and the owner is the caller — a forged `user` must not let a caller
        // count against, or borrow, somebody else's quota.
        verify(this.sessionsIndex).countForUser(eq(CALLER), any());
    }

    // ---------------------------------------------------------------------------------------------
    // UPDATE
    // ---------------------------------------------------------------------------------------------

    public void testUpdateCarriesOverTheStoredOwnerAndCreationInstants() {
        mockFindHit(storedSession());
        mockReplace("9:1");

        PutAiAssistantSessionResponse response =
                execute(
                        Operation.UPDATE,
                        SESSION_ID,
                        "{\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],"
                                + "\"user\":\"admin\",\"created_at\":\"2000-01-01T00:00:00Z\"}");

        assertEquals(RestStatus.OK, response.getStatus());
        Map<String, Object> written = capturedReplace();
        assertEquals(CALLER, written.get(AiAssistantSessionsIndex.USER_FIELD));
        assertEquals("2026-09-01T10:00:00Z", written.get(AiAssistantSessionsIndex.CREATED_AT_FIELD));
        assertEquals("2026-09-01T10:00:00Z", written.get(AiAssistantSessionsIndex.TIMESTAMP_FIELD));
        // updated_at IS re-stamped by a replace.
        assertNotEquals("2026-09-01T10:30:00Z", written.get(AiAssistantSessionsIndex.UPDATED_AT_FIELD));
        assertEquals(1, ((List<?>) written.get(AiAssistantSessionsIndex.MESSAGES_FIELD)).size());
        assertEquals("9:1", response.getBody().get("version"));

        // The lookup is scoped to the caller, which is what makes another user's id a 404.
        verify(this.sessionsIndex).findHit(eq(CALLER), eq(SESSION_ID), any());
    }

    public void testUpdateWithoutATitleKeepsTheStoredOne() {
        mockFindHit(storedSession());
        mockReplace("9:1");
        execute(Operation.UPDATE, SESSION_ID, "{\"messages\":[]}");
        // The rename-reversion guard: an auto-save that resends only the transcript must not
        // overwrite a title the user has just changed.
        assertEquals("stored title", capturedReplace().get(AiAssistantSessionsIndex.TITLE_FIELD));
    }

    public void testUpdateWithATitleReplacesIt() {
        mockFindHit(storedSession());
        mockReplace("9:1");
        execute(Operation.UPDATE, SESSION_ID, "{\"messages\":[],\"title\":\"  new  \"}");
        assertEquals("new", capturedReplace().get(AiAssistantSessionsIndex.TITLE_FIELD));
    }

    public void testUpdateRejectsATitleThatIsPresentButBlank() {
        mockFindHit(storedSession());
        assertBadRequest(
                execute(Operation.UPDATE, SESSION_ID, "{\"messages\":[],\"title\":\"  \"}"),
                "Session title is required.");
    }

    public void testUpdateUsesTheClientVersionWhenItIsDecodable() {
        mockFindHit(storedSession());
        mockReplace("9:1");
        execute(Operation.UPDATE, SESSION_ID, "{\"messages\":[],\"expected_version\":\"4:2\"}");
        verify(this.sessionsIndex).replace(any(), any(), eq(4L), eq(2L), any());
    }

    public void testUpdateFallsBackToTheFreshlyReadPair() {
        mockFindHit(storedSession());
        mockReplace("9:1");
        // An undecodable token is treated as absent, not rejected. The platform still requires a
        // pair on a backing-index write, so the one just read is used — the check simply narrows to
        // "since this request started".
        execute(Operation.UPDATE, SESSION_ID, "{\"messages\":[],\"expected_version\":\"garbage\"}");
        verify(this.sessionsIndex).replace(any(), any(), eq(8L), eq(1L), any());
    }

    public void testUpdateOfAnUnknownOrForeignSessionIsNotFound() {
        mockFindHit(null);
        // 404 rather than 403 on purpose: a 403 would confirm that another user's session id exists.
        Exception e =
                expectThrows(
                        ResourceNotFoundException.class,
                        () -> execute(Operation.UPDATE, SESSION_ID, "{\"messages\":[]}"));
        assertEquals("Session not found: " + SESSION_ID, e.getMessage());
        verify(this.sessionsIndex, never()).replace(any(), any(), anyLong(), anyLong(), any());
    }

    public void testUpdateSurfacesAVersionConflict() {
        mockFindHit(storedSession());
        mockReplaceConflict();
        PutAiAssistantSessionResponse response =
                execute(Operation.UPDATE, SESSION_ID, "{\"messages\":[],\"expected_version\":\"1:1\"}");
        // Never retried with a fresh pair: retrying is exactly the silent overwrite
        // expected_version exists to prevent.
        assertEquals(RestStatus.CONFLICT, response.getStatus());
        assertEquals(
                "Session was updated by another session since you last loaded it. Refresh and retry.",
                response.getBody().get("message"));
    }

    // ---------------------------------------------------------------------------------------------
    // RENAME
    // ---------------------------------------------------------------------------------------------

    public void testRenameChangesOnlyTheTitleAndLeavesUpdatedAtAlone() {
        mockFindHit(storedSession());
        mockReplace("10:1");

        PutAiAssistantSessionResponse response =
                execute(Operation.RENAME, SESSION_ID, "{\"title\":\"  renamed  \"}");

        Map<String, Object> written = capturedReplace();
        assertEquals("renamed", written.get(AiAssistantSessionsIndex.TITLE_FIELD));
        // A rename is not session activity; re-stamping updated_at would reorder the session list.
        assertEquals("2026-09-01T10:30:00Z", written.get(AiAssistantSessionsIndex.UPDATED_AT_FIELD));
        assertEquals(CALLER, written.get(AiAssistantSessionsIndex.USER_FIELD));
        assertEquals("2026-09-01T10:00:00Z", written.get(AiAssistantSessionsIndex.CREATED_AT_FIELD));
        assertEquals(2, ((List<?>) written.get(AiAssistantSessionsIndex.MESSAGES_FIELD)).size());

        assertEquals(RestStatus.OK, response.getStatus());
        assertEquals(SESSION_ID, response.getBody().get("id"));
        assertEquals("renamed", response.getBody().get("title"));
        assertEquals("2026-09-01T10:30:00Z", response.getBody().get("updated_at"));
        // The write's own fresh version, so a client renaming the session it has open does not
        // conflict on its next auto-save.
        assertEquals("10:1", response.getBody().get("version"));
        assertFalse(response.getBody().containsKey("messages"));
    }

    public void testRenameRequiresATitle() {
        assertBadRequest(execute(Operation.RENAME, SESSION_ID, "{}"), "Session title is required.");
        assertBadRequest(
                execute(Operation.RENAME, SESSION_ID, "{\"title\":\"\\t \"}"),
                "Session title is required.");
        verify(this.sessionsIndex, never()).findHit(any(), any(), any());
    }

    public void testRenameOfAForeignSessionIsNotFound() {
        mockFindHit(null);
        expectThrows(
                ResourceNotFoundException.class,
                () -> execute(Operation.RENAME, SESSION_ID, "{\"title\":\"x\"}"));
        verify(this.sessionsIndex, never()).replace(any(), any(), anyLong(), anyLong(), any());
    }

    // ---------------------------------------------------------------------------------------------
    // DELETE
    // ---------------------------------------------------------------------------------------------

    public void testDeleteReturnsTheEnvelope() {
        mockFindHit(storedSession());
        doAnswer(
                        invocation -> {
                            this.<String>listenerOf(invocation.getArgument(1)).onResponse(SESSION_ID);
                            return null;
                        })
                .when(this.sessionsIndex)
                .delete(any(), any());

        PutAiAssistantSessionResponse response = execute(Operation.DELETE, SESSION_ID, null);
        assertEquals(RestStatus.OK, response.getStatus());
        // DELETE keeps the house {message, status, id} envelope: it has nothing to round-trip.
        assertEquals("Session deleted.", response.getBody().get("message"));
        assertEquals(200, response.getBody().get("status"));
        assertEquals(SESSION_ID, response.getBody().get("id"));
    }

    public void testDeleteOfAForeignSessionIsNotFoundAndWritesNothing() {
        mockFindHit(null);
        expectThrows(
                ResourceNotFoundException.class, () -> execute(Operation.DELETE, SESSION_ID, null));
        verify(this.sessionsIndex, never()).delete(any(), any());
    }

    // ---------------------------------------------------------------------------------------------
    // Harness
    // ---------------------------------------------------------------------------------------------

    private PutAiAssistantSessionResponse execute(
            Operation operation, String sessionId, String payload) {
        PlainActionFuture<PutAiAssistantSessionResponse> future = PlainActionFuture.newFuture();
        this.action.doExecute(
                mock(Task.class), new PutAiAssistantSessionRequest(operation, sessionId, payload), future);
        return future.actionGet();
    }

    private static void assertBadRequest(PutAiAssistantSessionResponse response, String message) {
        // A 400 arrives via onResponse, not onFailure, so the body is the {message, status}
        // envelope rather than OpenSearch's error shape. See the setup plugin's other endpoints.
        assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        assertEquals(message, response.getBody().get("message"));
        assertEquals(400, response.getBody().get("status"));
    }

    private static SessionHit storedSession() {
        Map<String, Object> source = new LinkedHashMap<>();
        source.put(AiAssistantSessionsIndex.USER_FIELD, CALLER);
        source.put(AiAssistantSessionsIndex.TITLE_FIELD, "stored title");
        source.put(
                AiAssistantSessionsIndex.MESSAGES_FIELD,
                List.of(Map.of("role", "user"), Map.of("role", "assistant")));
        source.put(AiAssistantSessionsIndex.CREATED_AT_FIELD, "2026-09-01T10:00:00Z");
        source.put(AiAssistantSessionsIndex.UPDATED_AT_FIELD, "2026-09-01T10:30:00Z");
        source.put(AiAssistantSessionsIndex.TIMESTAMP_FIELD, "2026-09-01T10:00:00Z");
        return new SessionHit(SESSION_ID, BACKING_INDEX, 8L, 1L, source);
    }

    private void mockCount(long count) {
        doAnswer(
                        invocation -> {
                            this.<Long>listenerOf(invocation.getArgument(1)).onResponse(count);
                            return null;
                        })
                .when(this.sessionsIndex)
                .countForUser(any(), any());
    }

    private void mockCreate(String id, String version) {
        doAnswer(
                        invocation -> {
                            this.<SessionWrite>listenerOf(invocation.getArgument(1))
                                    .onResponse(new SessionWrite(id, version));
                            return null;
                        })
                .when(this.sessionsIndex)
                .create(any(), any());
    }

    private void mockFindHit(SessionHit hit) {
        doAnswer(
                        invocation -> {
                            this.<SessionHit>listenerOf(invocation.getArgument(2)).onResponse(hit);
                            return null;
                        })
                .when(this.sessionsIndex)
                .findHit(any(), any(), any());
    }

    private void mockReplace(String version) {
        doAnswer(
                        invocation -> {
                            this.<SessionWrite>listenerOf(invocation.getArgument(4))
                                    .onResponse(new SessionWrite(SESSION_ID, version));
                            return null;
                        })
                .when(this.sessionsIndex)
                .replace(any(), any(), anyLong(), anyLong(), any());
    }

    private void mockReplaceConflict() {
        doAnswer(
                        invocation -> {
                            this.<SessionWrite>listenerOf(invocation.getArgument(4))
                                    .onFailure(
                                            new VersionConflictEngineException(
                                                    new ShardId(BACKING_INDEX, "uuid", 0), SESSION_ID, "conflict"));
                            return null;
                        })
                .when(this.sessionsIndex)
                .replace(any(), any(), anyLong(), anyLong(), any());
    }

    @SuppressWarnings("unchecked")
    private <T> ActionListener<T> listenerOf(Object argument) {
        return (ActionListener<T>) argument;
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> capturedCreate() {
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(this.sessionsIndex).create(captor.capture(), any());
        return captor.getValue();
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> capturedReplace() {
        ArgumentCaptor<Map<String, Object>> captor = ArgumentCaptor.forClass(Map.class);
        verify(this.sessionsIndex).replace(any(), captor.capture(), anyLong(), anyLong(), any());
        return captor.getValue();
    }
}
