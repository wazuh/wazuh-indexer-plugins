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

import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.cluster.health.ClusterHealthRequestBuilder;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.ClusterAdminClient;
import org.opensearch.transport.client.IndicesAdminClient;

import java.io.IOException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.utils.JsonUtils;

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
        // Verify that the policies were indexed (6 policies: events, findings, raw-events,
        // active-responses, metrics, ai-assistant-sessions)
        verify(this.client, times(6)).index(any(IndexRequest.class));
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
     * Verifies that if the ISM policy file is missing or cannot be loaded, {@link
     * IndexStateManagement#initialize()} handles the {@link IOException} without throwing it.
     *
     * @throws IOException if there is an error reading the policy file
     */
    public void testPolicyFileMissing_LogsError() throws IOException {
        doReturn(true).when(this.ismIndex).indexExists(IndexStateManagement.ISM_INDEX_NAME);
        // Mock all policy file reads to throw IOException
        doThrow(new IOException("file not found")).when(jsonUtils).fromFile(anyString());

        this.ismIndex.initialize();

        // Verifies that exception is caught and logged
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
     * Verifies that IOException while reading a file is caught and logged.
     *
     * @throws IOException if there is an error reading the file
     */
    public void testFileIOException() throws IOException {
        doThrow(new IOException("Test failed successfully")).when(this.jsonUtils).fromFile(anyString());
        this.ismIndex.indexPolicy("test-template");
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
                        IndexStateManagement.AI_ASSISTANT_SESSIONS_POLICY);

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
}
