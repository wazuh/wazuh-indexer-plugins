package com.wazuh.setup.index;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;

import com.wazuh.setup.utils.IndexTemplateUtils;
import java.io.IOException;
import org.junit.runner.RunWith;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;

public class IsmIndexInitializerTests extends OpenSearchTestCase {

    private Client client;
    private RoutingTable routingTable;
    private IsmIndexInitializer ismIndexInitializer;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.client = mock(Client.class);
        this.routingTable = mock(RoutingTable.class);
        ismIndexInitializer = IsmIndexInitializer.getInstance()
            .setClient(this.client)
            .setRoutingTable(this.routingTable);

    }

    public void testGetInstance() {
        assert IsmIndexInitializer.getInstance().equals(this.ismIndexInitializer);
    }

    public void testIsmIndexExists() {

        // Test when the index does not exist
        doReturn(false).when(this.routingTable).hasIndex(anyString());
        assertFalse(this.ismIndexInitializer.ismIndexExists(IndexStrategySelector.ISM.getIndexName()));

        // Test when the index exists
        doReturn(true).when(this.routingTable).hasIndex(anyString());
        assert this.ismIndexInitializer.ismIndexExists(IndexStrategySelector.ISM.getIndexName());
    }

    public void testInitIndexCreatesIsmIndex() {
        AdminClient adminClient = mock(AdminClient.class);
        doReturn(adminClient).when(this.client).admin();
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        doReturn(indicesAdminClient).when(adminClient).indices();
        ActionFuture<CreateIndexResponse> createIndexResponseActionFuture = mock(ActionFuture.class);
        doReturn(createIndexResponseActionFuture)
            .when(indicesAdminClient)
            .create(any(CreateIndexRequest.class));
        ActionFuture<IndexResponse> indexResponseActionFuture = mock(ActionFuture.class);
        doReturn(indexResponseActionFuture).when(this.client).index(any(IndexRequest.class));
        this.ismIndexInitializer.initIndex(IndexStrategySelector.ISM);
        verify(indicesAdminClient, times(1)).create(any(CreateIndexRequest.class));
    }

    public void testInitIndexException() throws IOException {
        AdminClient adminClient = mock(AdminClient.class);
        doReturn(adminClient).when(this.client).admin();
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        doReturn(indicesAdminClient).when(adminClient).indices();
        ActionFuture<CreateIndexResponse> createIndexResponseActionFuture = mock(ActionFuture.class);
        doReturn(createIndexResponseActionFuture)
            .when(indicesAdminClient)
            .create(any(CreateIndexRequest.class));
        ActionFuture<IndexResponse> indexResponseActionFuture = mock(ActionFuture.class);
        doReturn(indexResponseActionFuture).when(this.client).index(any(IndexRequest.class));

        this.ismIndexInitializer.initIndex(IndexStrategySelector.ISM);
        verify(indicesAdminClient, times(1)).create(any(CreateIndexRequest.class));
    }

}
