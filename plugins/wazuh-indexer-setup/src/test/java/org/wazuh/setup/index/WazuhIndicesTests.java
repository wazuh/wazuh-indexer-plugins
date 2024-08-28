package org.wazuh.setup.index;

import org.junit.Before;
import org.junit.Ignore;
import org.mockito.*;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.ClusterState;

import org.opensearch.test.OpenSearchTestCase;
import org.wazuh.setup.utils.IndexTemplateUtils;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class WazuhIndicesTests extends OpenSearchTestCase {

    @Mock
    private Client client;

    @Mock
    private ClusterService clusterService;

    @Mock
    private AdminClient adminClient;

    @Mock
    private IndicesAdminClient indicesAdminClient;

    @Mock
    private ClusterState clusterState;

    @Mock
    private RoutingTable routingTable;

    @InjectMocks
    private WazuhIndices wazuhIndices;

    @Captor
    private ArgumentCaptor<PutIndexTemplateRequest> putIndexTemplateRequestCaptor;

    @Captor
    private ArgumentCaptor<CreateIndexRequest> createIndexRequestCaptor;

    @Before
    public void setup() {
        this.client = mock(Client.class);
        this.adminClient = mock(AdminClient.class);
        this.indicesAdminClient = mock(IndicesAdminClient.class);
        this.clusterService = mock(ClusterService.class);
        this.clusterState = mock(ClusterState.class);
        this.routingTable = mock(RoutingTable.class);

        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(clusterService.state()).thenReturn(clusterState);
        when(clusterState.getRoutingTable()).thenReturn(routingTable);

        this.wazuhIndices = new WazuhIndices(this.client, this.clusterService);
    }

    // FIXME The used MockMaker SubclassByteBuddyMockMaker does not support the creation of static mocks
    // adding mockito-inline seems to have no effect
    @Ignore
    public void testPutTemplate_Successful() {
        // Arrange
        String templateName = "index-template-agent";
        Map<String, Object> template = new HashMap<>();
        template.put("mappings", new HashMap<>());
        template.put("settings", new HashMap<>());
        template.put("index_patterns", new HashMap<>());

        // Mock the static method call
        try (MockedStatic<IndexTemplateUtils> mockedStatic = Mockito.mockStatic(IndexTemplateUtils.class)) {
            mockedStatic.when(() -> IndexTemplateUtils.fromFile(eq(templateName + ".json"))).thenReturn(template);

            when(indicesAdminClient.putTemplate(any(PutIndexTemplateRequest.class)).actionGet())
                    .thenReturn(mock(AcknowledgedResponse.class));

            // Act
            wazuhIndices.putTemplate(templateName);

            // Assert
            verify(indicesAdminClient).putTemplate(putIndexTemplateRequestCaptor.capture());
            PutIndexTemplateRequest capturedRequest = putIndexTemplateRequestCaptor.getValue();

            assertEquals(templateName, capturedRequest.name());
            assertNotNull(capturedRequest.mappings());
            assertNotNull(capturedRequest.settings());
        }
    }

    // FIXME The used MockMaker SubclassByteBuddyMockMaker does not support the creation of static mocks
    // adding mockito-inline seems to have no effect
    @Ignore
    public void testPutTemplate_IOException() {
        // Arrange
        String templateName = "index-template-agent";

        // Mock the static method to throw IOException
        try (MockedStatic<IndexTemplateUtils> mockedStatic = Mockito.mockStatic(IndexTemplateUtils.class)) {
            mockedStatic.when(() -> IndexTemplateUtils.fromFile(eq(templateName + ".json"))).thenThrow(IOException.class);

            // Act
            wazuhIndices.putTemplate(templateName);

            // Assert
            verify(indicesAdminClient, never()).putTemplate(any(PutIndexTemplateRequest.class));
        }
    }

    // FIXME the return value of "org.opensearch.client.IndicesAdminClient.create(org.opensearch.action.admin.indices.create.CreateIndexRequest)" is null
    @Ignore
    public void testPutIndex_IndexDoesNotExist() {
        // Arrange
        String indexName = ".agents";
        CreateIndexResponse createIndexResponse = new CreateIndexResponse(
                true,
                true,
                indexName
        );

        when(routingTable.hasIndex(indexName)).thenReturn(false);
        when(indicesAdminClient.create(any(CreateIndexRequest.class)).actionGet())
                .thenReturn(createIndexResponse);

        // Act
        wazuhIndices.putIndex(indexName);

        // Assert
        verify(indicesAdminClient).create(createIndexRequestCaptor.capture());
        CreateIndexRequest capturedRequest = createIndexRequestCaptor.getValue();

        assertEquals(indexName, capturedRequest.index());
    }


    public void testPutIndex_IndexExists() {
        // Arrange
        String indexName = ".agents";
        when(routingTable.hasIndex(indexName)).thenReturn(true);

        // Act
        wazuhIndices.putIndex(indexName);

        // Assert
        verify(indicesAdminClient, never()).create(any(CreateIndexRequest.class));
    }


    public void testIndexExists() {
        // Arrange
        String indexName = ".agents";
        when(routingTable.hasIndex(indexName)).thenReturn(true);

        // Act
        boolean exists = wazuhIndices.indexExists(indexName);

        // Assert
        assertTrue(exists);
    }


    @Ignore
    public void testInitialize() throws IOException {
        // Arrange
        String templateName = "index-template-agent";
        String indexName = ".agents";

        Map<String, Object> template = new HashMap<>();
        template.put("mappings", new HashMap<>());
        template.put("settings", new HashMap<>());
        template.put("index_patterns", new HashMap<>());

        when(IndexTemplateUtils.fromFile(eq(templateName + ".json"))).thenReturn(template);
        when(routingTable.hasIndex(indexName)).thenReturn(false);
        when(indicesAdminClient.putTemplate(any(PutIndexTemplateRequest.class)).actionGet())
                .thenReturn(mock(AcknowledgedResponse.class));
        when(indicesAdminClient.create(any(CreateIndexRequest.class)).actionGet())
                .thenReturn(mock(CreateIndexResponse.class));

        // Act
        wazuhIndices.initialize();

        // Assert
        verify(indicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class));
        verify(indicesAdminClient).create(any(CreateIndexRequest.class));
    }
}

