/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.setup;

import com.wazuh.setup.index.WazuhIndices;
import org.junit.After;
import org.junit.Before;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;

import static org.mockito.Mockito.*;
import static org.opensearch.test.ClusterServiceUtils.createClusterService;

public class SetupPluginTests extends OpenSearchTestCase {

    public static final String INDEX_NAME = "wazuh-indexer-setup-test-index";
    public ClusterService clusterService;
    private WazuhIndices wazuhIndices;
    private ThreadPool threadPool;
    private Client mockClient;

    /**
     * Creates the necessary mocks and spies
     */
    @Before
    public void setUp() throws Exception {
        try {
            super.setUp();

            this.threadPool = new TestThreadPool("WazuhIndexerSetupPluginServiceTests");
            this.clusterService = spy(createClusterService(threadPool));
            this.mockClient = mock(Client.class);
            this.wazuhIndices = new WazuhIndices(mockClient, clusterService);
        } catch (Exception e) {
            fail(e.toString());
        }
    }

    /**
     * Shuts the test cluster down properly after tests are done
     */
    @After
    public void testTearDown() {
        this.threadPool.shutdownNow();
        this.clusterService.close();
    }

    /**
     * Tests the putTemplate method
     */
    @AwaitsFix(bugUrl = "")
    public void testPutTemplate() {
        String mockTemplateName = "anIndexTemplateName";

        AdminClient mockAdminClient = mock(AdminClient.class);
        IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
        when(this.mockClient.admin()).thenReturn(mockAdminClient);
        when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);

        doAnswer(invocation -> {
            ActionListener<AcknowledgedResponse> listener = invocation.getArgument(1);
            listener.onResponse(new AcknowledgedResponse(true));
            return null;
        }).when(mockIndicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class), any(ActionListener.class));

        try {
            this.wazuhIndices.putTemplate(mockTemplateName);
        } catch (Exception e) {
            fail(e.toString());
        }

        doAnswer(invocation -> {
            ActionListener<AcknowledgedResponse> listener = invocation.getArgument(1);
            listener.onFailure(new Exception("Mock exception on putTemplate"));
            return null;
        }).when(mockIndicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class), any(ActionListener.class));

        try {
            this.wazuhIndices.putTemplate(mockTemplateName);
        } catch (Exception e) {
            fail(e.toString());
        }
    }

    /**
     * Tests creating an index
     */
    @AwaitsFix(bugUrl = "")
    public void testCreate() {
        AdminClient mockAdminClient = mock(AdminClient.class);
        IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
        when(this.mockClient.admin()).thenReturn(mockAdminClient);
        when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);

        doAnswer(invocation -> {
            ActionListener<CreateIndexResponse> listener = invocation.getArgument(1);
            listener.onResponse(new CreateIndexResponse(true, true, INDEX_NAME));
            return null;
        }).when(mockIndicesAdminClient).create(any(CreateIndexRequest.class), any(ActionListener.class));

        ActionListener<CreateIndexResponse> actionListener = new ActionListener<>() {
            @Override
            public void onResponse(CreateIndexResponse createIndexResponse) {
                logger.info("Mock successful index creation");
                assertTrue(createIndexResponse.isAcknowledged());
            }

            @Override
            public void onFailure(Exception e) {
                logger.error("Mock error creating index: {}", e.toString());
            }
        };

        try {
            this.wazuhIndices.putIndex(INDEX_NAME);
        } catch (Exception e) {
            fail(e.toString());
        }

        doAnswer(invocation -> {
            ActionListener<CreateIndexResponse> listener = invocation.getArgument(1);
            listener.onFailure(new Exception("Mock Exception"));
            return null;
        }).when(mockIndicesAdminClient).create(any(CreateIndexRequest.class), any(ActionListener.class));

        try {
            this.wazuhIndices.putIndex(INDEX_NAME);
        } catch (Exception e) {
            fail(e.toString());
        }
    }

    /**
     * Tests the indexExists() method
     */
    public void testIndexExists() {
        ClusterState mockClusterState = mock(ClusterState.class);
        RoutingTable mockRoutingTable = mock(RoutingTable.class);
        when(this.clusterService.state()).thenReturn(mockClusterState);
        when(mockClusterState.getRoutingTable()).thenReturn(mockRoutingTable);
        /* Test with existent index response */
        when(mockRoutingTable.hasIndex(anyString())).thenReturn(true);
        logger.error(this.wazuhIndices.indexExists(INDEX_NAME));
        /* Test with non-existent index response */
        when(mockRoutingTable.hasIndex(anyString())).thenReturn(false);
        logger.error(this.wazuhIndices.indexExists(INDEX_NAME));
    }
}
