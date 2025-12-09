package com.wazuh.contentmanager.cti.catalog.index;

import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.junit.After;
import org.junit.Before;
import org.mockito.Answers;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.cluster.health.ClusterHealthStatus;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

public class ConsumersIndexTests extends OpenSearchTestCase {

    private ConsumersIndex consumersIndex;
    private AutoCloseable closeable;
    private Client client;

    @Mock private IndexResponse indexResponse;
    @Mock private GetResponse getResponse;
    @Mock private ClusterHealthResponse clusterHealthResponse;
    @Mock private IndicesExistsResponse indicesExistsResponse;
    @Mock private CreateIndexResponse createIndexResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.client = mock(Client.class, Answers.RETURNS_DEEP_STUBS);
        Settings settings = Settings.builder().build();
        PluginSettings.getInstance(settings);
        this.consumersIndex = new ConsumersIndex(this.client);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /**
     * Tests that setConsumer constructs the correct ID (context_name) and performs the index operation.
     */
    public void testSetConsumer_Success() throws Exception {
        // Mock
        when(this.client.admin().cluster().prepareHealth().setIndices(anyString()).setWaitForYellowStatus().get())
            .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(ClusterHealthStatus.GREEN);

        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);

        // Act
        LocalConsumer consumer = new LocalConsumer("test_context", "test_consumer", 100L, 200L, "http://snapshot");
        this.consumersIndex.setConsumer(consumer);

        // Assert
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());

        IndexRequest request = captor.getValue();
        assertEquals(ConsumersIndex.INDEX_NAME, request.index());
        assertEquals("test_context_test_consumer", request.id());
    }

    /**
     * Tests that setConsumer throws a RuntimeException if the cluster status is RED.
     */
    public void testSetConsumer_IndexNotReady() {
        // Mock
        when(this.client.admin().cluster().prepareHealth().setIndices(anyString()).setWaitForYellowStatus().get())
            .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(ClusterHealthStatus.RED);

        LocalConsumer consumer = new LocalConsumer("ctx", "name");

        // Act and Assert
        RuntimeException ex = assertThrows(RuntimeException.class, () -> this.consumersIndex.setConsumer(consumer));
        assertEquals("Index not ready", ex.getMessage());
    }

    /**
     * Tests getConsumer retrieves the correct document ID based on context and consumer name.
     */
    public void testGetConsumer_Success() throws Exception {
        // Mock
        when(this.client.admin().cluster().prepareHealth().setIndices(anyString()).setWaitForYellowStatus().get())
            .thenReturn(this.clusterHealthResponse);
        when(this.clusterHealthResponse.getStatus()).thenReturn(ClusterHealthStatus.YELLOW);

        PlainActionFuture<GetResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.getResponse);
        when(this.client.get(any(GetRequest.class))).thenReturn(future);

        // Act
        this.consumersIndex.getConsumer("my_context", "my_consumer");

        // Assert
        ArgumentCaptor<GetRequest> captor = ArgumentCaptor.forClass(GetRequest.class);
        verify(this.client).get(captor.capture());

        GetRequest request = captor.getValue();
        assertEquals(ConsumersIndex.INDEX_NAME, request.index());
        assertEquals("my_context_my_consumer", request.id());
    }

    /**
     * Tests exists() delegates correctly to the IndicesExistsRequest.
     */
    public void testExists() {
        // Mock
        when(this.client.admin().indices().exists(any(IndicesExistsRequest.class)).actionGet())
            .thenReturn(this.indicesExistsResponse);
        when(this.indicesExistsResponse.isExists()).thenReturn(true);

        // Clear invocations to ensure verify only counts the actual method call
        clearInvocations(this.client.admin().indices());

        // Act
        boolean result = this.consumersIndex.exists();

        // Assert
        assertTrue(result);
        ArgumentCaptor<IndicesExistsRequest> captor = ArgumentCaptor.forClass(IndicesExistsRequest.class);
        verify(this.client.admin().indices()).exists(captor.capture());
        assertArrayEquals(new String[]{ConsumersIndex.INDEX_NAME}, captor.getValue().indices());
    }

    /**
     * Tests createIndex().
     */
    public void testCreateIndex() throws Exception {
        // Mock
        PlainActionFuture<CreateIndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.createIndexResponse);
        when(this.client.admin().indices().create(any(CreateIndexRequest.class))).thenReturn(future);

        ConsumersIndex spyIndex = spy(this.consumersIndex);
        doReturn("{}").when(spyIndex).loadMappingFromResources();

        // Act
        spyIndex.createIndex();

        // Assert
        ArgumentCaptor<CreateIndexRequest> captor = ArgumentCaptor.forClass(CreateIndexRequest.class);
        verify(this.client.admin().indices()).create(captor.capture());

        CreateIndexRequest request = captor.getValue();
        assertEquals(ConsumersIndex.INDEX_NAME, request.index());

        // Validate Settings (Hidden = true, Replicas = 0)
        assertEquals("true", request.settings().get("hidden"));
        assertEquals("0", request.settings().get("index.number_of_replicas"));
    }
}
