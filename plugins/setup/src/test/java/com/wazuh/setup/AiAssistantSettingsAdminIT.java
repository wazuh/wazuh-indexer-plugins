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
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

import static org.hamcrest.Matchers.containsString;

/**
 * Integration tests for the administrative AI assistant settings API, which reads and writes the
 * assistant's settings/field policy ({@code /_plugins/_setup/ai_assistant/settings}) and providers
 * ({@code /_plugins/_setup/ai_assistant/providers[/{id}]}) in the shared {@code
 * .wazuh-internal-state} index. Both document kinds are flat at the root — no {@code settings}/
 * {@code providers} wrapper object. Security is not enabled in this test cluster, so these tests
 * cover the endpoints' functional behavior; the system-index lockout itself is validated against a
 * live, security-enabled cluster (see the setup plugin's development documentation).
 *
 * <p>{@code .wazuh-internal-state} is normally created by the content-manager plugin, which is not
 * installed in this test module, so each test creates it directly with a mapping mirroring the
 * generated one closely enough to exercise the endpoints.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.SUITE)
public class AiAssistantSettingsAdminIT extends OpenSearchRestTestCase {

    private static final String SETTINGS_URI = "/_plugins/_setup/ai_assistant/settings";
    private static final String PROVIDERS_URI = "/_plugins/_setup/ai_assistant/providers";
    private static final String INDEX_NAME = ".wazuh-internal-state";
    private static final String SETTINGS_DOCUMENT_ID = "wazuh-ai-assistant-settings";
    private static final String CREDENTIALS_DOCUMENT_ID = "credentials";
    private static final String PROVIDERS_FIELD = "providers";
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
     * DataStreamsIT}) depend on the events/findings data streams the setup plugin creates once at
     * node bootstrap surviving for the life of the whole {@code integTest} run; without this
     * override, this class's default teardown wipes them cluster-wide.
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
     * Creates {@code .wazuh-internal-state} if it does not already exist, with a flat mapping
     * covering every field the endpoints read or write plus the content-manager-owned {@code
     * access_token}.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    @Before
    public void ensureIndexExists() throws IOException {
        Request request = new Request("PUT", "/" + INDEX_NAME);
        request.setJsonEntity(
                "{\"settings\":{\"index\":{\"hidden\":true}},"
                        + "\"mappings\":{\"dynamic\":\"strict\",\"properties\":{"
                        + "\"access_token\":{\"type\":\"keyword\",\"index\":false},"
                        + "\"privacy_default_on\":{\"type\":\"boolean\"},"
                        + "\"privacy_default_per_provider\":{\"type\":\"flat_object\"},"
                        + "\"user_can_override\":{\"type\":\"boolean\"},"
                        + "\"field_policy\":{\"properties\":{"
                        + "\"field\":{\"type\":\"keyword\"},"
                        + "\"action\":{\"type\":\"keyword\"},"
                        + "\"kind\":{\"type\":\"keyword\"}}},"
                        + "\"name\":{\"type\":\"keyword\"},"
                        + "\"type\":{\"type\":\"keyword\"},"
                        + "\"base_url\":{\"type\":\"keyword\"},"
                        + "\"model\":{\"type\":\"keyword\"},"
                        + "\"api_key\":{\"type\":\"keyword\"},"
                        + "\"is_default\":{\"type\":\"boolean\"},"
                        + "\"updated_at\":{\"type\":\"date\"}"
                        + "}}}");
        try {
            client().performRequest(request);
        } catch (ResponseException e) {
            if (!e.getMessage().contains("resource_already_exists_exception")) {
                throw e;
            }
        }
    }

    /**
     * Verifies that the settings document round-trips through a PUT/GET pair, flat at the root (no
     * {@code settings} wrapper key), and that the response never contains the content-manager-owned
     * {@code access_token}.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testPutAndGetSettingsRoundTrips() throws IOException, ParseException {
        Request put = new Request("PUT", SETTINGS_URI);
        put.setJsonEntity(
                "{\"privacy_default_on\":true,\"privacy_default_per_provider\":{},"
                        + "\"user_can_override\":false,"
                        + "\"field_policy\":[{\"field\":\"wazuh.agent.id\",\"action\":\"allow\"}]}");
        Response putResponse = client().performRequest(put);
        assertEquals(200, putResponse.getStatusLine().getStatusCode());

        Response getResponse = client().performRequest(new Request("GET", SETTINGS_URI));
        String body = EntityUtils.toString(getResponse.getEntity(), StandardCharsets.UTF_8);

        logger.info("Get settings response: {}", body);
        assertThat(body, containsString("\"privacy_default_on\":true"));
        assertThat(body, containsString("\"user_can_override\":false"));
        assertThat(body, containsString("\"wazuh.agent.id\""));
        assertThat(body, containsString("\"allow\""));
        org.junit.Assert.assertFalse(body.contains("access_token"));
        org.junit.Assert.assertFalse(body.contains("\"providers\""));

        JsonNode settingsDoc = getDocById(SETTINGS_DOCUMENT_ID);
        org.junit.Assert.assertTrue(
                "Settings document should exist under the reserved id", settingsDoc != null);
    }

    /**
     * Verifies that a {@code privacy_default_per_provider} map keyed by runtime-generated provider
     * ids is accepted and round-trips. The keys are UUIDs minted by the client, so under this
     * index's {@code dynamic: strict} mapping the field has to be a {@code flat_object}: as a plain
     * {@code object} every new key was rejected with a {@code strict_dynamic_mapping_exception}.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testPutSettingsAcceptsUnknownProviderIdKeys() throws IOException, ParseException {
        String firstProviderId = java.util.UUID.randomUUID().toString();
        String secondProviderId = java.util.UUID.randomUUID().toString();

        Request put = new Request("PUT", SETTINGS_URI);
        put.setJsonEntity(
                "{\"privacy_default_on\":false,\"user_can_override\":true,"
                        + "\"privacy_default_per_provider\":{\""
                        + firstProviderId
                        + "\":true,\""
                        + secondProviderId
                        + "\":false}}");
        Response putResponse = client().performRequest(put);
        assertEquals(200, putResponse.getStatusLine().getStatusCode());

        Response getResponse = client().performRequest(new Request("GET", SETTINGS_URI));
        String body = EntityUtils.toString(getResponse.getEntity(), StandardCharsets.UTF_8);

        logger.info("Get settings response: {}", body);
        assertThat(body, containsString(firstProviderId));
        assertThat(body, containsString(secondProviderId));
    }

    /**
     * Verifies that creating a provider without an {@code id} is rejected with {@code 400}: the
     * client must always supply one.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testCreateProviderRequiresId() throws IOException {
        Request create = new Request("POST", PROVIDERS_URI);
        create.setJsonEntity(
                "{\"name\":\"test-ai\",\"type\":\"anthropic\","
                        + "\"base_url\":\"https://api.anthropic.com\",\"model\":\"claude-opus-4-6\","
                        + "\"api_key\":\"secret\",\"is_default\":true}");

        ResponseException exception =
                expectThrows(ResponseException.class, () -> client().performRequest(create));
        assertEquals(400, exception.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Verifies that a client-supplied {@code id} in the create body is honored when it is a valid
     * UUID, that it is stripped from the stored provider fields, that the list entry is flat, and
     * that a client-supplied {@code updated_at} is discarded in favor of a server-stamped timestamp.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testCreateProviderWithClientSuppliedUuid() throws IOException, ParseException {
        String uuid = java.util.UUID.randomUUID().toString();
        Request create = new Request("POST", PROVIDERS_URI);
        create.setJsonEntity(
                "{\"id\":\""
                        + uuid
                        + "\",\"name\":\"client-uuid-ai\",\"type\":\"anthropic\","
                        + "\"base_url\":\"https://api.anthropic.com\",\"model\":\"claude-opus-4-6\","
                        + "\"api_key\":\"secret\",\"is_default\":true,"
                        + "\"updated_at\":\"2000-01-01T00:00:00.000Z\"}");
        Response createResponse = client().performRequest(create);
        String createBody = EntityUtils.toString(createResponse.getEntity(), StandardCharsets.UTF_8);
        logger.info("Create-with-uuid response: {}", createBody);
        assertEquals(200, createResponse.getStatusLine().getStatusCode());
        assertThat(createBody, containsString(uuid));

        Response getResponse = client().performRequest(new Request("GET", PROVIDERS_URI));
        String body = EntityUtils.toString(getResponse.getEntity(), StandardCharsets.UTF_8);
        logger.info("Provider list response: {}", body);

        JsonNode entry = findProviderById(body, uuid);
        org.junit.Assert.assertNotNull("Created provider not found in list", entry);
        assertEquals("client-uuid-ai", entry.path("name").asText());
        assertEquals("anthropic", entry.path("type").asText());
        org.junit.Assert.assertFalse(
                "Provider entry must be flat, not nested under 'providers'", entry.has(PROVIDERS_FIELD));
        org.junit.Assert.assertFalse(
                "Client-supplied updated_at must be discarded",
                "2000-01-01T00:00:00.000Z".equals(entry.path("updated_at").asText()));
        org.junit.Assert.assertFalse(entry.path("updated_at").asText().isEmpty());
    }

    private static JsonNode findProviderById(String listResponseBody, String id) throws IOException {
        JsonNode providers = MAPPER.readTree(listResponseBody).path(PROVIDERS_FIELD);
        for (JsonNode entry : providers) {
            if (id.equals(entry.path("_id").asText())) {
                return entry;
            }
        }
        return null;
    }

    private static JsonNode getDocById(String id) throws IOException {
        try {
            Response response =
                    client().performRequest(new Request("GET", "/" + INDEX_NAME + "/_doc/" + id));
            return MAPPER.readTree(EntityUtils.toString(response.getEntity(), StandardCharsets.UTF_8));
        } catch (ResponseException | ParseException e) {
            return null;
        }
    }

    /**
     * Verifies that a non-UUID {@code id} in the create body is rejected with {@code 400}.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testCreateProviderRejectsNonUuidId() throws IOException {
        Request create = new Request("POST", PROVIDERS_URI);
        create.setJsonEntity(
                "{\"id\":\"not-a-uuid\",\"name\":\"bad-id-ai\",\"type\":\"anthropic\","
                        + "\"base_url\":\"https://api.anthropic.com\",\"model\":\"claude-opus-4-6\","
                        + "\"api_key\":\"secret\",\"is_default\":true}");

        ResponseException exception =
                expectThrows(ResponseException.class, () -> client().performRequest(create));
        assertEquals(400, exception.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Verifies that {@code PUT}/{@code DELETE} on a reserved document id ({@code
     * wazuh-ai-assistant-settings}, {@code credentials}) is rejected with {@code 400}, instead of
     * silently overwriting or deleting the settings document or content-manager's credentials.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testProviderWriteRejectsReservedIds() throws IOException {
        for (String reservedId : new String[] {SETTINGS_DOCUMENT_ID, CREDENTIALS_DOCUMENT_ID}) {
            Request put = new Request("PUT", PROVIDERS_URI + "/" + reservedId);
            put.setJsonEntity(
                    "{\"name\":\"attacker-ai\",\"type\":\"anthropic\","
                            + "\"base_url\":\"https://api.anthropic.com\",\"model\":\"claude-opus-4-6\","
                            + "\"api_key\":\"secret\",\"is_default\":true}");
            ResponseException putException =
                    expectThrows(ResponseException.class, () -> client().performRequest(put));
            assertEquals(400, putException.getResponse().getStatusLine().getStatusCode());

            Request delete = new Request("DELETE", PROVIDERS_URI + "/" + reservedId);
            ResponseException deleteException =
                    expectThrows(ResponseException.class, () -> client().performRequest(delete));
            assertEquals(400, deleteException.getResponse().getStatusLine().getStatusCode());
        }
    }

    /**
     * Verifies that a provider created with an explicit id can be updated in place, and then deleted;
     * a second delete reports {@code 404}.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testPutAndDeleteProviderByExplicitId() throws IOException, ParseException {
        String providerId = "explicit-provider";
        Request put = new Request("PUT", PROVIDERS_URI + "/" + providerId);
        put.setJsonEntity(
                "{\"name\":\"explicit-ai\",\"type\":\"openai\","
                        + "\"base_url\":\"https://api.openai.com\",\"model\":\"gpt-5\","
                        + "\"api_key\":\"secret\",\"is_default\":false}");
        assertEquals(200, client().performRequest(put).getStatusLine().getStatusCode());

        Response listResponse = client().performRequest(new Request("GET", PROVIDERS_URI));
        String body = EntityUtils.toString(listResponse.getEntity(), StandardCharsets.UTF_8);
        assertThat(body, containsString("\"explicit-ai\""));
        assertThat(body, containsString(providerId));

        Response deleteResponse =
                client().performRequest(new Request("DELETE", PROVIDERS_URI + "/" + providerId));
        assertEquals(200, deleteResponse.getStatusLine().getStatusCode());

        Response afterDelete = client().performRequest(new Request("GET", PROVIDERS_URI));
        String afterDeleteBody = EntityUtils.toString(afterDelete.getEntity(), StandardCharsets.UTF_8);
        org.junit.Assert.assertFalse(afterDeleteBody.contains(providerId));

        ResponseException secondDelete =
                expectThrows(
                        ResponseException.class,
                        () -> client().performRequest(new Request("DELETE", PROVIDERS_URI + "/" + providerId)));
        assertEquals(404, secondDelete.getResponse().getStatusLine().getStatusCode());
    }

    /**
     * Verifies that the provider list never includes the reserved settings ({@code
     * "wazuh-ai-assistant-settings"}) or credentials ({@code "credentials"}) documents.
     *
     * @throws IOException if there is an issue with the HTTP request
     * @throws ParseException if there is an issue parsing the response
     */
    public void testProviderListExcludesReservedDocuments() throws IOException, ParseException {
        Request put = new Request("PUT", SETTINGS_URI);
        put.setJsonEntity(
                "{\"privacy_default_on\":true,\"privacy_default_per_provider\":{},"
                        + "\"user_can_override\":false,\"field_policy\":[]}");
        assertEquals(200, client().performRequest(put).getStatusLine().getStatusCode());

        Response listResponse = client().performRequest(new Request("GET", PROVIDERS_URI));
        String body = EntityUtils.toString(listResponse.getEntity(), StandardCharsets.UTF_8);
        logger.info("Provider list response: {}", body);
        org.junit.Assert.assertFalse(body.contains("\"_id\":\"" + SETTINGS_DOCUMENT_ID + "\""));
        org.junit.Assert.assertFalse(body.contains("\"_id\":\"" + CREDENTIALS_DOCUMENT_ID + "\""));
    }

    /**
     * Verifies that the strict mapping still rejects an unknown field sent through the endpoint's
     * write path, once a valid {@code id} clears the id-required check.
     *
     * @throws IOException if there is an issue with the HTTP request
     */
    public void testPutSettingsRejectsUnknownField() throws IOException {
        String uuid = java.util.UUID.randomUUID().toString();
        Request create = new Request("POST", PROVIDERS_URI);
        create.setJsonEntity(
                "{\"id\":\"" + uuid + "\",\"name\":\"test-ai\",\"unexpected_field\":\"value\"}");

        ResponseException exception =
                expectThrows(ResponseException.class, () -> client().performRequest(create));
        assertEquals(400, exception.getResponse().getStatusLine().getStatusCode());
    }
}
