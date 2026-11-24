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

import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequestBuilder;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.ClusterAdminClient;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.Assert;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import com.wazuh.setup.config.SetupConfig;
import com.wazuh.setup.utils.JsonUtils;
import org.mockito.ArgumentCaptor;

import static org.mockito.Mockito.*;

/** Unit tests for the {@link IndexStateManagement} class. */
public class IndexStateManagementTests extends OpenSearchTestCase {

    private IndexStateManagement ismIndex;
    private Client client;
    private IndicesAdminClient indicesAdminClient;
    private ClusterAdminClient clusterAdminClient;
    private JsonUtils jsonUtils;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        this.client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        this.clusterAdminClient = mock(ClusterAdminClient.class);
        this.jsonUtils = mock(JsonUtils.class);

        // Default settings
        ClusterService clusterService = mock(ClusterService.class);
        Settings settings = Settings.builder().build();
        doReturn(settings).when(clusterService).getSettings();

        doReturn(adminClient).when(this.client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();
        doReturn(this.clusterAdminClient).when(adminClient).cluster();

        // Stub the health-wait chain used in initialize() so it does not NPE.
        ClusterHealthRequestBuilder healthBuilder =
                mock(ClusterHealthRequestBuilder.class, RETURNS_SELF);
        doReturn(healthBuilder).when(this.clusterAdminClient).prepareHealth(anyString());
        ActionFuture<ClusterHealthResponse> healthFuture = mock(ActionFuture.class);
        doReturn(healthFuture).when(healthBuilder).execute();
        doReturn(mock(ClusterHealthResponse.class)).when(healthFuture).actionGet(anyLong());

        this.ismIndex =
                spy(new IndexStateManagement(IndexStateManagement.ISM_INDEX_NAME, "templates/ism-config"));
        this.ismIndex.setClient(this.client);
        this.ismIndex.setUtils(this.jsonUtils);
        this.ismIndex.setClusterService(clusterService);
    }

    /**
     * Verifies that {@link IndexStateManagement#initialize()} creates the index and indexes ISM
     * policies when the index does not already exist.
     *
     * @throws IOException if an error occurs while reading the policy file
     */
    public void testInitialize_CreatesIndexAndPolicies() throws IOException {
        // Mock indexExists to return false so createIndex is called
        doReturn(false).when(this.ismIndex).indexExists(IndexStateManagement.ISM_INDEX_NAME);

        // Mock the CreateIndexResponse
        CreateIndexResponse createResponse = mock(CreateIndexResponse.class);
        doReturn(IndexStateManagement.ISM_INDEX_NAME).when(createResponse).index();

        ActionFuture<CreateIndexResponse> createIndexFuture = mock(ActionFuture.class);
        doReturn(createResponse).when(createIndexFuture).actionGet(anyLong());
        doReturn(createIndexFuture).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        // Mock the policy file loading for all policies
        Map<String, Object> policyFile = Map.of("policy", "definition");
        doReturn(policyFile).when(this.jsonUtils).fromFile(anyString());

        // Mock the policy indexing
        ActionFuture indexFuture = mock(ActionFuture.class);
        doReturn(indexFuture).when(this.client).index(any(IndexRequest.class));
        doReturn(null).when(indexFuture).actionGet(anyLong());

        this.ismIndex.initialize();

        // Verify that the index was created with the correct request
        verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
        // Verify that the policies were indexed (7 policies: events, findings, raw-events,
        // active-responses, metrics, ai-assistant-sessions, security-auditlogs)
        verify(this.client, times(7)).index(any(IndexRequest.class));
    }

    /**
     * Verifies that if the index already exists, {@link IndexStateManagement#initialize()} skips
     * index creation.
     */
    public void testIndexAlreadyExists_SkipsCreation() {
        doReturn(true).when(this.ismIndex).indexExists(IndexStateManagement.ISM_INDEX_NAME);

        doReturn(mock(ActionFuture.class)).when(this.client).index(any(IndexRequest.class));

        this.ismIndex.initialize();

        verify(this.indicesAdminClient, never()).create(any());
    }

    /**
     * Verifies that a bundled ISM policy that cannot be read fails {@link
     * IndexStateManagement#initialize()} with an error naming the policy, with no retry and no other
     * policy stored.
     *
     * @throws IOException if there is an error reading the policy file
     */
    public void testBundledPolicyThatCannotBeRead_FailsTheInitialization() throws IOException {
        doReturn(true).when(this.ismIndex).indexExists(IndexStateManagement.ISM_INDEX_NAME);
        doThrow(new IOException("unexpected end of input")).when(this.jsonUtils).fromFile(anyString());

        UncheckedIOException e =
                LuceneTestCase.expectThrows(UncheckedIOException.class, () -> this.ismIndex.initialize());

        Assert.assertEquals(
                "ISM policy ["
                        + IndexStateManagement.POLICIES.get(0)
                        + "] bundled in the plugin cannot be read: unexpected end of input",
                e.getMessage());
        verify(this.jsonUtils, times(1)).fromFile(anyString());
        verify(this.client, never()).index(any(IndexRequest.class));
    }

    /**
     * Verifies that if the ISM policy already exists in the index, {@link
     * IndexStateManagement#initialize()} handles the {@link ResourceAlreadyExistsException}
     * gracefully without failing.
     *
     * @throws IOException if there is an error reading the policy file
     */
    public void testPolicyAlreadyExists_LogsInfo() throws IOException {
        doReturn(true).when(this.ismIndex).indexExists(IndexStateManagement.ISM_INDEX_NAME);

        // Mock all policy file reads
        Map<String, Object> policyFile = Map.of("policy", "definition");
        doReturn(policyFile).when(jsonUtils).fromFile(anyString());
        doThrow(new ResourceAlreadyExistsException("already exists"))
                .when(this.client)
                .index(any(IndexRequest.class));

        this.ismIndex.initialize();

        // Verifies that exception is caught and logged
    }

    /**
     * Verifies that {@link IndexStateManagement#applyIsmTemplateTimestamp(Map)} copies the policy's
     * timestamp into the templates that do not declare one, and leaves the ones that do untouched.
     */
    public void testApplyIsmTemplateTimestamp_CopiesThePolicyTimestamp() {
        Map<String, Object> withoutTimestamp = new HashMap<>();
        withoutTimestamp.put("index_patterns", List.of("a-*"));
        Map<String, Object> withTimestamp = new HashMap<>();
        withTimestamp.put("index_patterns", List.of("b-*"));
        withTimestamp.put("last_updated_time", 1L);

        Map<String, Object> policy = new HashMap<>();
        policy.put("last_updated_time", 1772122150000L);
        policy.put("ism_template", List.of(withoutTimestamp, withTimestamp));
        Map<String, Object> policyFile = new HashMap<>();
        policyFile.put("policy", policy);

        IndexStateManagement.applyIsmTemplateTimestamp(policyFile);

        assertEquals(1772122150000L, withoutTimestamp.get("last_updated_time"));
        assertEquals(1L, withTimestamp.get("last_updated_time"));
    }

    /**
     * Verifies that {@link IndexStateManagement#applyIsmTemplateTimestamp(Map)} also copies the
     * policy's timestamp into an {@code ism_template} written as a single template, which ISM accepts
     * as well as a list.
     */
    public void testApplyIsmTemplateTimestamp_SingleTemplate() {
        Map<String, Object> template = new HashMap<>();
        template.put("index_patterns", List.of("a-*"));
        Map<String, Object> policy = new HashMap<>();
        policy.put("last_updated_time", 1772122150000L);
        policy.put("ism_template", template);
        Map<String, Object> policyFile = new HashMap<>();
        policyFile.put("policy", policy);

        IndexStateManagement.applyIsmTemplateTimestamp(policyFile);

        Assert.assertEquals(1772122150000L, template.get("last_updated_time"));
    }

    /** Verifies that a policy without an {@code ism_template} is left alone. */
    public void testApplyIsmTemplateTimestamp_IgnoresPoliciesWithoutTemplates() {
        Map<String, Object> policyFile = new HashMap<>();
        policyFile.put("policy", "definition");

        IndexStateManagement.applyIsmTemplateTimestamp(policyFile);

        assertEquals("definition", policyFile.get("policy"));
    }

    /**
     * Verifies that every shipped policy ends up with a timestamp in each of its {@code ism_template}
     * entries, and that the timestamp is in the past. Without it ISM stamps the template with the
     * current time on every read and the template matches no index at all; a timestamp ahead of the
     * deployment clock reproduces the same failure, because ISM only applies a template to indices
     * created after it.
     *
     * @throws IOException if a policy file cannot be read
     */
    @SuppressWarnings("unchecked")
    public void testShippedPolicies_DeclareAnIsmTemplateTimestamp() throws IOException {
        JsonUtils utils = new JsonUtils();
        List<String> shipped =
                List.of(
                        IndexStateManagement.EVENTS_POLICY,
                        IndexStateManagement.FINDINGS_POLICY,
                        IndexStateManagement.RAW_EVENTS_POLICY,
                        IndexStateManagement.ACTIVE_RESPONSES_POLICY,
                        IndexStateManagement.METRICS_POLICY,
                        IndexStateManagement.AI_ASSISTANT_SESSIONS_POLICY,
                        IndexStateManagement.SECURITY_AUDITLOGS_POLICY);

        for (String name : shipped) {
            Map<String, Object> policyFile =
                    utils.fromFile(IndexStateManagement.POLICIES_PATH + name + ".json");
            IndexStateManagement.applyIsmTemplateTimestamp(policyFile);

            Map<String, Object> policy = (Map<String, Object>) policyFile.get("policy");
            Object lastUpdatedTime = policy.get("last_updated_time");
            assertNotNull(name + " declares no last_updated_time", lastUpdatedTime);
            assertTrue(
                    name + " declares a last_updated_time that is not in the past",
                    ((Number) lastUpdatedTime).longValue() < System.currentTimeMillis());

            List<Object> templates = (List<Object>) policy.get("ism_template");
            assertNotNull(name + " declares no ism_template", templates);
            assertFalse(name + " declares an empty ism_template", templates.isEmpty());
            for (Object template : templates) {
                assertEquals(
                        name + " has a template without the policy timestamp",
                        lastUpdatedTime,
                        ((Map<String, Object>) template).get("last_updated_time"));
            }
        }
    }

    /**
     * Verifies that the policies of the streams that roll over by volume delete a backing index a
     * fixed time after it rolled over, with no other condition. A deletion age counted from the index
     * creation is always met by an index that took longer than that age to fill, so the index would
     * be deleted as soon as it rolls over and the history would drop to almost nothing at every
     * rollover. The two streams that roll over by age keep counting from the creation.
     *
     * @throws IOException if a policy file cannot be read
     */
    @SuppressWarnings("unchecked")
    public void testShippedPolicies_DeletionAgeCountsFromTheRollover() throws IOException {
        JsonUtils utils = new JsonUtils();
        Map<String, Map<String, String>> expected =
                Map.of(
                        IndexStateManagement.EVENTS_POLICY, Map.of("min_rollover_age", "1h"),
                        IndexStateManagement.RAW_EVENTS_POLICY, Map.of("min_rollover_age", "4h"),
                        IndexStateManagement.FINDINGS_POLICY, Map.of("min_rollover_age", "90d"),
                        IndexStateManagement.METRICS_POLICY, Map.of("min_rollover_age", "30d"),
                        IndexStateManagement.ACTIVE_RESPONSES_POLICY, Map.of("min_rollover_age", "3d"),
                        IndexStateManagement.AI_ASSISTANT_SESSIONS_POLICY, Map.of("min_index_age", "7d"),
                        IndexStateManagement.SECURITY_AUDITLOGS_POLICY, Map.of("min_index_age", "90d"));

        for (Map.Entry<String, Map<String, String>> entry : expected.entrySet()) {
            Map<String, Object> policyFile =
                    utils.fromFile(IndexStateManagement.POLICIES_PATH + entry.getKey() + ".json");
            Map<String, Object> policy = (Map<String, Object>) policyFile.get("policy");

            Map<String, Object> hot = null;
            for (Object state : (List<Object>) policy.get("states")) {
                if ("hot".equals(((Map<String, Object>) state).get("name"))) {
                    hot = (Map<String, Object>) state;
                }
            }
            assertNotNull(entry.getKey() + " has no hot state", hot);

            List<Object> transitions = (List<Object>) hot.get("transitions");
            assertEquals(entry.getKey() + " must have one transition", 1, transitions.size());
            Map<String, Object> transition = (Map<String, Object>) transitions.get(0);
            assertEquals(entry.getKey(), "delete", transition.get("state_name"));
            assertEquals(entry.getKey(), entry.getValue(), transition.get("conditions"));
        }
    }

    /**
     * A policy whose creation keeps timing out is retried up to {@code plugins.setup.max_retries}
     * times and then the failure is rethrown. {@code indexPolicy} retries by calling itself, so a
     * counter reset inside it would retry forever: the mock fails the test after 20 calls instead of
     * letting it hang.
     */
    public void testIndexPolicy_StopsAfterMaxRetries() throws IOException {
        doNothing().when(this.ismIndex).sleep(anyLong());
        Map<String, Object> policyFile = new HashMap<>();
        policyFile.put("policy", new HashMap<String, Object>());
        doReturn(policyFile).when(this.jsonUtils).fromFile(anyString());

        AtomicInteger attempts = new AtomicInteger();
        ActionFuture<?> indexFuture = mock(ActionFuture.class);
        doAnswer(
                        invocation -> {
                            if (attempts.incrementAndGet() > 20) {
                                throw new AssertionError("indexPolicy is still retrying after 20 attempts");
                            }
                            throw new RuntimeException("simulated timeout");
                        })
                .when(indexFuture)
                .actionGet(anyLong());
        doReturn(indexFuture).when(this.client).index(any(IndexRequest.class));

        assertThrows(RuntimeException.class, () -> this.ismIndex.indexPolicy("wazuh-events"));
        // Default plugins.setup.max_retries is 1: the first attempt plus one retry.
        assertEquals(2, attempts.get());
    }

    /**
     * Every policy times out once and then succeeds. The retry budget is per policy, so with the
     * default of one retry all seven recover; a budget shared across policies would rethrow on the
     * second one.
     */
    public void testInitialize_EachPolicyGetsItsOwnRetryBudget() throws IOException {
        doNothing().when(this.ismIndex).sleep(anyLong());
        doReturn(true).when(this.ismIndex).indexExists(IndexStateManagement.ISM_INDEX_NAME);
        Map<String, Object> policyFile = new HashMap<>();
        policyFile.put("policy", new HashMap<String, Object>());
        doReturn(policyFile).when(this.jsonUtils).fromFile(anyString());

        AtomicInteger calls = new AtomicInteger();
        ActionFuture<?> indexFuture = mock(ActionFuture.class);
        doAnswer(
                        invocation -> {
                            if (calls.incrementAndGet() % 2 == 1) {
                                throw new RuntimeException("simulated timeout");
                            }
                            return null;
                        })
                .when(indexFuture)
                .actionGet(anyLong());
        doReturn(indexFuture).when(this.client).index(any(IndexRequest.class));

        this.ismIndex.initialize();

        // Seven policies, each one timeout plus one successful retry.
        verify(this.client, times(14)).index(any(IndexRequest.class));
    }

    /**
     * Makes the configuration file of the plugin replace the events policy with a policy file.
     *
     * @throws IOException if a file cannot be written.
     */
    private void replaceTheEventsPolicy() throws IOException {
        Path directory = LuceneTestCase.createTempDir();
        Files.writeString(
                directory.resolve(SetupConfig.FILE),
                "policies." + IndexStateManagement.EVENTS_POLICY + ".custom: true\n",
                StandardCharsets.UTF_8);
        Files.writeString(
                directory.resolve(IndexStateManagement.EVENTS_POLICY + ".json"),
                "{\"policy\": {\"policy_id\": \""
                        + IndexStateManagement.EVENTS_POLICY
                        + "\", \"description\": \"Edited copy\", \"last_updated_time\": 1700000000000,"
                        + " \"default_state\": \"hot\", \"states\": [{\"name\": \"hot\"}],"
                        + " \"ism_template\": [{\"index_patterns\": [\"wazuh-events-v5*\"], \"priority\": 0}]}}",
                StandardCharsets.UTF_8);
        this.ismIndex.setConfig(
                SetupConfig.load(
                        directory, List.of(), IndexStateManagement.POLICIES, NamedXContentRegistry.EMPTY));
        doReturn(mock(ActionFuture.class)).when(this.client).index(any(IndexRequest.class));
    }

    /**
     * A policy the configuration file replaces is indexed from its policy file, under the id of the
     * default policy, with its timestamp copied to the template as for a bundled policy. The bundled
     * policy is not read.
     *
     * @throws IOException if a file cannot be written.
     */
    @SuppressWarnings("unchecked")
    public void testIndexPolicy_UsesThePolicyFileOfAReplacedPolicy() throws IOException {
        this.replaceTheEventsPolicy();

        this.ismIndex.indexPolicy(IndexStateManagement.EVENTS_POLICY);

        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        Assert.assertEquals(IndexStateManagement.EVENTS_POLICY, captor.getValue().id());
        Map<String, Object> policy =
                (Map<String, Object>) captor.getValue().sourceAsMap().get("policy");
        Assert.assertEquals("Edited copy", policy.get("description"));
        Map<String, Object> template = ((List<Map<String, Object>>) policy.get("ism_template")).get(0);
        Assert.assertEquals(policy.get("last_updated_time"), template.get("last_updated_time"));
        verify(this.jsonUtils, never()).fromFile(anyString());
    }

    /**
     * The policies the configuration file does not replace are still the bundled ones.
     *
     * @throws IOException if a file cannot be written.
     */
    public void testIndexPolicy_UsesTheBundledPolicyOfTheOthers() throws IOException {
        this.replaceTheEventsPolicy();
        doReturn(new HashMap<String, Object>()).when(this.jsonUtils).fromFile(anyString());

        this.ismIndex.indexPolicy(IndexStateManagement.FINDINGS_POLICY);

        verify(this.jsonUtils)
                .fromFile(
                        IndexStateManagement.POLICIES_PATH + IndexStateManagement.FINDINGS_POLICY + ".json");
    }
}
