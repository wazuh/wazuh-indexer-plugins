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
package com.wazuh.setup;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.core5.http.ParseException;
import org.apache.hc.core5.http.io.entity.EntityUtils;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.test.rest.OpenSearchRestTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

/**
 * Integration tests for the AI assistant sessions write API — {@code POST}/{@code PUT}/{@code
 * PATCH}/{@code DELETE} on {@code /_plugins/_setup/ai_assistant/sessions}, which mediates every
 * write to the {@code wazuh-ai-assistant-sessions} data stream so that a session's {@code user}
 * field is stamped by the server instead of being taken from the request body
 * (internal-devel-requests#6111).
 *
 * <p>There are no read endpoints by design: listing sessions and reading a transcript stay direct
 * index queries under the {@code wazuh_ai_assistant} role's document-level security filter, which
 * scopes reads correctly. So every assertion about what was actually stored here reads the document
 * back out of the index directly, exactly as the Dashboard does.
 *
 * <p><b>What this class cannot cover.</b> Security is not enabled in this test cluster, so there is
 * exactly one identity and no {@code _opendistro_security_user_info} transient: every session is
 * stamped with the {@code _shared} sentinel ({@link com.wazuh.setup.utils.AuthenticatedUser}). That
 * still exercises the whole stamp-and-scope path — the stamped owner is what the ownership filter
 * then matches on — but it cannot demonstrate the impersonation refusal, which needs a second user.
 * That half is covered by {@code TransportPutAiAssistantSessionActionTests} for the stamping logic
 * and by a run against a live, security-enabled cluster for the end-to-end behaviour, the same
 * split {@link AiAssistantSettingsAdminIT} documents.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class AiAssistantSessionsIT extends OpenSearchRestTestCase {

    private static final String SESSIONS_URI = "/_plugins/_setup/ai_assistant/sessions";
    private static final String STREAM_NAME = "wazuh-ai-assistant-sessions";
    private static final String SHARED_OWNER = "_shared";

    /** Mirrors {@code AiAssistantSessionsIndex.MAX_SESSIONS_PER_USER}. */
    private static final int MAX_SESSIONS_PER_USER = 500;

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * Preserves indices upon test completion to prevent the test framework from deleting indices
     * created by the SetupPlugin between tests.
     *
     * @return true to preserve indices
     */
    @Override
    protected boolean preserveIndicesUponCompletion() {
        return true;
    }

    /**
     * Preserves data streams upon test completion. Other IT classes in this module (e.g. {@code
     * DataStreamsIT}) depend on the data streams the setup plugin creates once at node bootstrap
     * surviving for the life of the whole {@code integTest} run; without this override, this class's
     * default teardown wipes them cluster-wide — including the one under test here.
     *
     * @return true to preserve data streams
     */
    @Override
    protected boolean preserveDataStreamsUponCompletion() {
        return true;
    }

    /**
     * Preserves index templates upon test completion, for the same reason as {@link
     * #preserveDataStreamsUponCompletion()}.
     *
     * @return true to preserve templates
     */
    @Override
    protected boolean preserveTemplatesUponCompletion() {
        return true;
    }

    /**
     * Waits for the setup plugin to have created the sessions data stream.
     *
     * <p>The plugin provisions its indices asynchronously once the node is elected cluster manager,
     * so a test that never writes a session — the {@code 404} cases — can otherwise reach the
     * endpoint before the stream exists and get a {@code 404} about a missing index instead of a
     * missing session.
     *
     * @throws Exception if the stream does not appear in time
     */
    @Before
    public void waitForTheSessionsDataStream() throws Exception {
        assertBusy(
                () -> {
                    try {
                        client().performRequest(new Request("GET", "/_data_stream/" + STREAM_NAME));
                    } catch (IOException e) {
                        throw new AssertionError("sessions data stream not created yet", e);
                    }
                },
                60,
                java.util.concurrent.TimeUnit.SECONDS);
    }

    /**
     * Removes every session this test wrote. The data stream is shared with the rest of the {@code
     * integTest} run, so each test cleans up after itself rather than relying on teardown.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    @After
    public void deleteAllSessions() throws IOException {
        Request request = new Request("POST", "/" + STREAM_NAME + "/_delete_by_query");
        request.addParameter("refresh", "true");
        request.setJsonEntity("{\"query\":{\"match_all\":{}}}");
        client().performRequest(request);
    }

    // ---------------------------------------------------------------------------------------------
    // CREATE
    // ---------------------------------------------------------------------------------------------

    /**
     * A create returns the session with both an {@code id} and a {@code version}, and the stored
     * document carries the server-stamped owner.
     *
     * <p>The {@code version} on create matters: without it the client would have to do a read before
     * its first {@code PUT} could send {@code expected_version}.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testCreateStampsTheOwnerAndReturnsAVersion() throws IOException, ParseException {
        JsonNode created =
                post(
                        "{\"title\":\"Any brute force attempts today?\","
                                + "\"messages\":[{\"role\":\"user\",\"content\":\"hi\",\"createdAt\":1788961419723}]}");

        String id = created.get("id").asText();
        assertFalse("create must return an id", id.isEmpty());
        assertFalse("create must return a version", created.get("version").asText().isEmpty());
        assertEquals("Any brute force attempts today?", created.get("title").asText());
        assertEquals(1, created.get("messages").size());
        // created_at and updated_at are equal on create.
        assertEquals(created.get("created_at").asText(), created.get("updated_at").asText());
        // @timestamp is stored but not exposed.
        assertFalse(created.has("@timestamp"));

        JsonNode stored = storedSource(id);
        assertEquals(SHARED_OWNER, stored.get("user").asText());
        assertEquals("Any brute force attempts today?", stored.get("title").asText());
        assertEquals("hi", stored.get("messages").get(0).get("content").asText());
        // @timestamp is what the data stream requires; it always equals created_at.
        assertEquals(stored.get("created_at").asText(), stored.get("@timestamp").asText());
    }

    /**
     * Server-owned fields sent by the client are discarded rather than rejected, so a client may POST
     * back a document it previously read. This is the stamping test minus the identity half: with
     * security disabled there is only one principal, so what it proves is that the body cannot
     * influence {@code user}, {@code created_at} or {@code @timestamp} at all.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testCreateDiscardsClientSuppliedServerOwnedFields()
            throws IOException, ParseException {
        JsonNode created =
                post(
                        "{\"title\":\"forged\",\"messages\":[],"
                                + "\"user\":\"admin\","
                                + "\"created_at\":\"2000-01-01T00:00:00Z\","
                                + "\"updated_at\":\"2000-01-01T00:00:00Z\","
                                + "\"@timestamp\":\"2000-01-01T00:00:00Z\","
                                + "\"junk\":\"dropped\"}");

        JsonNode stored = storedSource(created.get("id").asText());
        assertNotEquals("admin", stored.get("user").asText());
        assertEquals(SHARED_OWNER, stored.get("user").asText());
        assertNotEquals("2000-01-01T00:00:00Z", stored.get("created_at").asText());
        assertNotEquals("2000-01-01T00:00:00Z", stored.get("updated_at").asText());
        assertNotEquals("2000-01-01T00:00:00Z", stored.get("@timestamp").asText());
        assertFalse("unknown keys must never reach the index", stored.has("junk"));
    }

    /**
     * A create returns {@code 200}, not {@code 201}, matching {@code POST /ai_assistant/providers}.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testCreateReturnsTwoHundredNotTwoHundredAndOne() throws IOException {
        Request request = new Request("POST", SESSIONS_URI);
        request.setJsonEntity("{\"title\":\"t\",\"messages\":[]}");
        assertEquals(200, client().performRequest(request).getStatusLine().getStatusCode());
    }

    /**
     * The create-path validation: a blank or over-long title, a missing transcript, an over-long
     * transcript and an empty body are all {@code 400}, and none of them writes anything.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testCreateValidation() throws IOException, ParseException {
        assertBadRequest("{\"title\":\"   \",\"messages\":[]}", "Session title is required.");
        assertBadRequest("{\"messages\":[]}", "Session title is required.");
        assertBadRequest(
                "{\"title\":\"" + "x".repeat(201) + "\",\"messages\":[]}",
                "Session title must be 200 characters or fewer.");
        assertBadRequest("{\"title\":\"t\"}", "Session messages are required.");
        assertBadRequest(
                "{\"title\":\"t\",\"messages\":[" + "{},".repeat(1000) + "{}]}",
                "A session cannot hold more than 1000 messages.");

        // An empty body is caught in ActionRequest.validate(), which surfaces as OpenSearch's own
        // 400 error envelope rather than the {message, status} one.
        Request empty = new Request("POST", SESSIONS_URI);
        ResponseException e =
                expectThrows(ResponseException.class, () -> client().performRequest(empty));
        assertEquals(400, e.getResponse().getStatusLine().getStatusCode());

        assertEquals(0, storedCount());
    }

    /**
     * A 200-character title is accepted; only 201 is not. Guards the boundary against an off-by-one.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testCreateAcceptsATitleAtTheLimit() throws IOException, ParseException {
        JsonNode created = post("{\"title\":\"" + "x".repeat(200) + "\",\"messages\":[]}");
        assertEquals(200, created.get("title").asText().length());
    }

    /**
     * At the per-owner cap a create is a {@code 409}, and an update of an existing session still
     * succeeds — the cap must not freeze a user out of the sessions they already have, since an
     * update adds no document.
     *
     * <p>The 500 sessions are seeded with a single bulk request straight into the data stream rather
     * than through 500 calls to the endpoint: the endpoint's own refresh policy would make that take
     * minutes, and what is under test here is the count check, not the create path.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testCreateAtTheCapConflictsWhileUpdateStillWorks()
            throws IOException, ParseException {
        String existing = post("{\"title\":\"mine\",\"messages\":[]}").get("id").asText();

        StringBuilder bulk = new StringBuilder();
        String now = "2026-09-01T10:00:00Z";
        for (int i = 0; i < MAX_SESSIONS_PER_USER - 1; i++) {
            bulk.append("{\"create\":{}}\n")
                    .append("{\"user\":\"")
                    .append(SHARED_OWNER)
                    .append("\",\"title\":\"seeded ")
                    .append(i)
                    .append("\",\"messages\":[],\"created_at\":\"")
                    .append(now)
                    .append("\",\"updated_at\":\"")
                    .append(now)
                    .append("\",\"@timestamp\":\"")
                    .append(now)
                    .append("\"}\n");
        }
        Request seed = new Request("POST", "/" + STREAM_NAME + "/_bulk");
        seed.addParameter("refresh", "true");
        seed.setJsonEntity(bulk.toString());
        assertFalse(parse(client().performRequest(seed)).get("errors").asBoolean());
        assertEquals(MAX_SESSIONS_PER_USER, storedCount());

        Request atCap = new Request("POST", SESSIONS_URI);
        atCap.setJsonEntity("{\"title\":\"one too many\",\"messages\":[]}");
        Response response = performAllowingError(atCap);
        assertEquals(409, response.getStatusLine().getStatusCode());
        assertEquals(
                "You have reached the maximum of 500 saved sessions.",
                parse(response).get("message").asText());
        assertEquals(MAX_SESSIONS_PER_USER, storedCount());

        // The cap applies to POST only.
        assertEquals(1, put(existing, "{\"messages\":[{\"role\":\"user\"}]}").get("messages").size());
    }

    // ---------------------------------------------------------------------------------------------
    // UPDATE
    // ---------------------------------------------------------------------------------------------

    /**
     * A replace swaps the transcript, carries {@code created_at}/{@code @timestamp} over untouched
     * and advances {@code updated_at}.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testUpdateReplacesTheTranscriptAndAdvancesUpdatedAt()
            throws IOException, ParseException {
        JsonNode created = post("{\"title\":\"t\",\"messages\":[{\"role\":\"user\"}]}");
        String id = created.get("id").asText();

        JsonNode updated =
                put(
                        id,
                        "{\"messages\":[{\"role\":\"user\",\"content\":\"one\"},"
                                + "{\"role\":\"assistant\",\"content\":\"two\"}]}");

        assertEquals(2, updated.get("messages").size());
        assertEquals(created.get("created_at").asText(), updated.get("created_at").asText());
        assertNotEquals(created.get("updated_at").asText(), updated.get("updated_at").asText());
        assertNotEquals(created.get("version").asText(), updated.get("version").asText());

        JsonNode stored = storedSource(id);
        assertEquals(2, stored.get("messages").size());
        assertEquals("two", stored.get("messages").get(1).get("content").asText());
        assertEquals(created.get("created_at").asText(), stored.get("@timestamp").asText());
        assertEquals(SHARED_OWNER, stored.get("user").asText());
    }

    /**
     * The rename-reversion guard: a {@code PUT} that omits {@code title} keeps the stored one. A chat
     * client auto-saves every turn, and resending a recomputed title would silently undo a rename the
     * user had just made.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testUpdateWithoutATitleKeepsTheStoredTitle() throws IOException, ParseException {
        String id = post("{\"title\":\"original\",\"messages\":[]}").get("id").asText();
        patch(id, "{\"title\":\"renamed by the user\"}");

        JsonNode updated = put(id, "{\"messages\":[{\"role\":\"user\"}]}");
        assertEquals("renamed by the user", updated.get("title").asText());
        assertEquals("renamed by the user", storedSource(id).get("title").asText());
    }

    /**
     * A {@code PUT} that does send a title replaces it.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testUpdateWithATitleReplacesIt() throws IOException, ParseException {
        String id = post("{\"title\":\"original\",\"messages\":[]}").get("id").asText();
        assertEquals("new", put(id, "{\"messages\":[],\"title\":\"  new  \"}").get("title").asText());
    }

    /**
     * A stale {@code expected_version} is a {@code 409}, and — the part a status-code-only assertion
     * would miss — the stored transcript is left exactly as it was. A conflict must never be retried
     * with a freshly read pair, because that is precisely the silent overwrite {@code
     * expected_version} exists to prevent.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testUpdateWithAStaleVersionConflictsAndWritesNothing()
            throws IOException, ParseException {
        String id =
                post("{\"title\":\"t\",\"messages\":[{\"role\":\"user\",\"content\":\"keep\"}]}")
                        .get("id")
                        .asText();
        // Move the session on, so the version captured at create is genuinely stale.
        put(id, "{\"messages\":[{\"role\":\"user\",\"content\":\"keep\"}]}");

        Request request = new Request("PUT", SESSIONS_URI + "/" + id);
        request.setJsonEntity(
                "{\"messages\":[{\"role\":\"user\",\"content\":\"clobber\"}],\"expected_version\":\"0:1\"}");
        Response response = performAllowingError(request);

        assertEquals(409, response.getStatusLine().getStatusCode());
        JsonNode body = parse(response);
        assertEquals(409, body.get("status").asInt());
        assertEquals(
                "Session was updated by another session since you last loaded it. Refresh and retry.",
                body.get("message").asText());

        assertEquals("keep", storedSource(id).get("messages").get(0).get("content").asText());
    }

    /**
     * An undecodable {@code expected_version} is treated as absent rather than rejected: the write
     * still succeeds, carrying the pair the request itself just read.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testUpdateWithAnUndecodableVersionSucceeds() throws IOException, ParseException {
        String id = post("{\"title\":\"t\",\"messages\":[]}").get("id").asText();
        JsonNode updated =
                put(id, "{\"messages\":[{\"role\":\"user\"}],\"expected_version\":\"WzEyLDFd\"}");
        assertEquals(1, updated.get("messages").size());
    }

    /**
     * A fresh {@code expected_version} — the one the previous write returned — succeeds, which is the
     * auto-save loop a chat client actually runs.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testUpdateWithTheVersionFromThePreviousWriteSucceeds()
            throws IOException, ParseException {
        JsonNode created = post("{\"title\":\"t\",\"messages\":[]}");
        String id = created.get("id").asText();

        JsonNode first =
                put(
                        id,
                        "{\"messages\":[{\"role\":\"user\"}],\"expected_version\":\""
                                + created.get("version").asText()
                                + "\"}");
        JsonNode second =
                put(
                        id,
                        "{\"messages\":[{\"role\":\"user\"},{\"role\":\"assistant\"}],"
                                + "\"expected_version\":\""
                                + first.get("version").asText()
                                + "\"}");
        assertEquals(2, second.get("messages").size());
    }

    /**
     * An unknown session id is a {@code 404}, rendered as OpenSearch's own error envelope because it
     * is produced by {@code onFailure(new ResourceNotFoundException(...))}.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testUpdateOfAnUnknownSessionIsNotFound() throws IOException {
        Request request = new Request("PUT", SESSIONS_URI + "/does-not-exist");
        request.setJsonEntity("{\"messages\":[]}");
        ResponseException e =
                expectThrows(ResponseException.class, () -> client().performRequest(request));
        assertEquals(404, e.getResponse().getStatusLine().getStatusCode());
        assertTrue(e.getMessage().contains("Session not found: does-not-exist"));
    }

    // ---------------------------------------------------------------------------------------------
    // RENAME
    // ---------------------------------------------------------------------------------------------

    /**
     * A rename changes the title, trims it, and leaves {@code updated_at} exactly where it was — a
     * rename is not session activity, and bumping it would jump the row to the top of a list ordered
     * by last activity.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testRenameTrimsTheTitleAndLeavesUpdatedAtUnchanged()
            throws IOException, ParseException {
        JsonNode created =
                post("{\"title\":\"original\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}]}");
        String id = created.get("id").asText();

        JsonNode renamed = patch(id, "{\"title\":\"  Agent 003 connectivity  \"}");

        assertEquals(id, renamed.get("id").asText());
        assertEquals("Agent 003 connectivity", renamed.get("title").asText());
        assertEquals(created.get("updated_at").asText(), renamed.get("updated_at").asText());
        // The write's own fresh version, so the open session does not 409 on its next auto-save.
        assertNotEquals(created.get("version").asText(), renamed.get("version").asText());
        assertFalse("a rename response carries no transcript", renamed.has("messages"));

        JsonNode stored = storedSource(id);
        assertEquals("Agent 003 connectivity", stored.get("title").asText());
        assertEquals(created.get("updated_at").asText(), stored.get("updated_at").asText());
        // Everything else is carried over.
        assertEquals("hi", stored.get("messages").get(0).get("content").asText());
        assertEquals(created.get("created_at").asText(), stored.get("created_at").asText());
        assertEquals(SHARED_OWNER, stored.get("user").asText());
    }

    /**
     * A rename whose fresh version is used by the following auto-save succeeds — the reason the
     * rename response carries a version at all.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testRenameVersionIsUsableByTheNextUpdate() throws IOException, ParseException {
        String id = post("{\"title\":\"t\",\"messages\":[]}").get("id").asText();
        JsonNode renamed = patch(id, "{\"title\":\"renamed\"}");
        JsonNode updated =
                put(
                        id,
                        "{\"messages\":[{\"role\":\"user\"}],\"expected_version\":\""
                                + renamed.get("version").asText()
                                + "\"}");
        assertEquals("renamed", updated.get("title").asText());
    }

    /**
     * A rename requires a non-blank title.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testRenameValidation() throws IOException, ParseException {
        String id = post("{\"title\":\"t\",\"messages\":[]}").get("id").asText();

        Request blank = new Request("PATCH", SESSIONS_URI + "/" + id);
        blank.setJsonEntity("{\"title\":\"   \"}");
        Response response = performAllowingError(blank);
        assertEquals(400, response.getStatusLine().getStatusCode());
        assertEquals("Session title is required.", parse(response).get("message").asText());

        assertEquals("t", storedSource(id).get("title").asText());
    }

    // ---------------------------------------------------------------------------------------------
    // DELETE
    // ---------------------------------------------------------------------------------------------

    /**
     * A delete removes the document and returns the house envelope; a second delete is a {@code 404}.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testDeleteRemovesTheSessionAndIsIdempotentlyNotFound()
            throws IOException, ParseException {
        String id = post("{\"title\":\"t\",\"messages\":[]}").get("id").asText();

        Response response = client().performRequest(new Request("DELETE", SESSIONS_URI + "/" + id));
        assertEquals(200, response.getStatusLine().getStatusCode());
        JsonNode body = parse(response);
        assertEquals("Session deleted.", body.get("message").asText());
        assertEquals(200, body.get("status").asInt());
        assertEquals(id, body.get("id").asText());

        assertNull("the document must be gone from the index", storedSource(id));

        ResponseException e =
                expectThrows(
                        ResponseException.class,
                        () -> client().performRequest(new Request("DELETE", SESSIONS_URI + "/" + id)));
        assertEquals(404, e.getResponse().getStatusLine().getStatusCode());
    }

    // ---------------------------------------------------------------------------------------------
    // Helpers
    // ---------------------------------------------------------------------------------------------

    /**
     * Performs a request and hands back the response even when the status is an error.
     *
     * <p>The low-level REST client throws {@link ResponseException} on any non-2xx, regardless of
     * whether the plugin produced the status through {@code onResponse} (a {@code 400}/{@code 409}
     * carrying the {@code {message, status}} envelope) or through {@code onFailure} (a {@code 404}
     * carrying OpenSearch's error envelope). Tests that assert on an error body need the response,
     * not the exception, so they go through here.
     */
    private Response performAllowingError(Request request) throws IOException {
        try {
            return client().performRequest(request);
        } catch (ResponseException e) {
            return e.getResponse();
        }
    }

    private JsonNode post(String body) throws IOException, ParseException {
        Request request = new Request("POST", SESSIONS_URI);
        request.setJsonEntity(body);
        return parse(client().performRequest(request));
    }

    private JsonNode put(String id, String body) throws IOException, ParseException {
        Request request = new Request("PUT", SESSIONS_URI + "/" + id);
        request.setJsonEntity(body);
        return parse(client().performRequest(request));
    }

    private JsonNode patch(String id, String body) throws IOException, ParseException {
        Request request = new Request("PATCH", SESSIONS_URI + "/" + id);
        request.setJsonEntity(body);
        return parse(client().performRequest(request));
    }

    private void assertBadRequest(String body, String message) throws IOException, ParseException {
        Request request = new Request("POST", SESSIONS_URI);
        request.setJsonEntity(body);
        Response response = performAllowingError(request);
        // A semantic 400 arrives via onResponse, so it carries the {message, status} envelope
        // rather than OpenSearch's error shape.
        assertEquals(400, response.getStatusLine().getStatusCode());
        JsonNode parsed = parse(response);
        assertEquals(message, parsed.get("message").asText());
        assertEquals(400, parsed.get("status").asInt());
    }

    /**
     * Reads a session straight out of the index, the way the Dashboard's read path does. A get-by-id
     * cannot be used: this is a data stream, and the get API cannot know which backing index holds a
     * given id.
     *
     * @return the document source, or {@code null} when no such document exists.
     */
    private JsonNode storedSource(String id) throws IOException, ParseException {
        Request request = new Request("GET", "/" + STREAM_NAME + "/_search");
        request.setJsonEntity("{\"query\":{\"ids\":{\"values\":[\"" + id + "\"]}},\"size\":1}");
        JsonNode hits = parse(client().performRequest(request)).get("hits").get("hits");
        return hits.isEmpty() ? null : hits.get(0).get("_source");
    }

    private long storedCount() throws IOException, ParseException {
        Request request = new Request("GET", "/" + STREAM_NAME + "/_count");
        return parse(client().performRequest(request)).get("count").asLong();
    }

    private static JsonNode parse(Response response) throws IOException, ParseException {
        return MAPPER.readTree(EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
    }
}
