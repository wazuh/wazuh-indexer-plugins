/*
 * Copyright (C) 2024, Wazuh Inc.
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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;
import com.wazuh.setup.utils.IndexUtils;

import static org.mockito.Mockito.*;

/** Unit tests for the {@link IndexStateManagement} class. */
public class IndexStateManagementTests extends OpenSearchTestCase {

    private IndexStateManagement ismIndex;
    private Client client;
    private IndicesAdminClient indicesAdminClient;
    private IndexUtils indexUtils;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        this.client = mock(Client.class);
        AdminClient adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        this.indexUtils = mock(IndexUtils.class);

        doReturn(adminClient).when(this.client).admin();
        doReturn(this.indicesAdminClient).when(adminClient).indices();

        this.ismIndex = spy(new IndexStateManagement(".opendistro-ism-config", "ism-template"));
        this.ismIndex.setClient(this.client);
        this.ismIndex.setIndexUtils(this.indexUtils);
    }

    /**
     * Verifies that {@link IndexStateManagement#initialize()} creates the index and indexes ISM
     * policies when the index does not already exist.
     *
     * @throws IOException if an error occurs while reading the policy file
     */
    public void testInitialize_CreatesIndexAndPolicies() throws IOException {
        Map<String, Object> template = new HashMap<>();
        template.put("settings", Settings.builder().build());
        template.put("mappings", Map.of());

        doReturn(false).when(this.ismIndex).indexExists(".opendistro-ism-config");
        doReturn(template).when(this.indexUtils).fromFile("ism-template.json");
        doReturn(template.get("mappings")).when(this.indexUtils).get(template, "mappings");

        CreateIndexResponse createResponse = mock(CreateIndexResponse.class);
        doReturn(".opendistro-ism-config").when(createResponse).index();

        ActionFuture actionFuture = mock(ActionFuture.class);

        doReturn(actionFuture).when(this.indicesAdminClient).create(any(CreateIndexRequest.class));

        Map<String, Object> policyFile = Map.of("policy", "definition");
        doReturn(policyFile).when(this.indexUtils).fromFile("wazuh-alerts-rollover-policy.json");

        doReturn(actionFuture).when(this.client).index(any(IndexRequest.class));

        doReturn(createResponse).when(actionFuture).actionGet(SetupPlugin.TIMEOUT);

        this.ismIndex.initialize();

        verify(this.indicesAdminClient).create(any(CreateIndexRequest.class));
        verify(this.client).index(any(IndexRequest.class));
    }

    /**
     * Verifies that if the index already exists, {@link IndexStateManagement#initialize()} skips
     * index creation.
     */
    public void testIndexAlreadyExists_SkipsCreation() {
        doReturn(true).when(this.ismIndex).indexExists(".opendistro-ism-config");

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
        doReturn(true).when(this.ismIndex).indexExists(".opendistro-ism-config");
        doThrow(new IOException("file not found"))
                .when(indexUtils)
                .fromFile("wazuh-alerts-rollover-policy.json");

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
        doReturn(true).when(this.ismIndex).indexExists(".opendistro-ism-config");

        Map<String, Object> policyFile = Map.of("policy", "definition");
        doReturn(policyFile).when(indexUtils).fromFile("wazuh-alerts-rollover-policy.json");
        doThrow(new ResourceAlreadyExistsException("already exists"))
                .when(this.client)
                .index(any(IndexRequest.class));

        this.ismIndex.initialize();

        // Verifies that exception is caught and logged
    }
}
