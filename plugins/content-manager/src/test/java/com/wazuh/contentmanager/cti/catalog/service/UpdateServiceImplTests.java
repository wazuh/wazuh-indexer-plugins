package com.wazuh.contentmanager.cti.catalog.service;

import com.google.gson.JsonObject;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.junit.After;
import org.junit.Before;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.transport.client.Client;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.times;

public class UpdateServiceImplTests extends OpenSearchTestCase {

    private UpdateServiceImpl updateService;
    private AutoCloseable closeable;

    @Mock private ApiClient apiClient;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private ContentIndex ruleIndex;
    @Mock private ContentIndex decoderIndex;
    @Mock private GetResponse getResponse;
    @Mock private Client client;
    @Mock private ActionFuture actionFuture;
    @Mock private ActionFuture<GetResponse> getResponseFuture;
    @Mock private SecurityAnalyticsService securityAnalyticsService;

    private Map<String, ContentIndex> indices;
    private static final String CONTEXT = "rules_dev";
    private static final String CONSUMER = "test_consumer";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);

        PluginSettings.getInstance(Settings.EMPTY);

        this.indices = new HashMap<>();
        this.indices.put("rule", this.ruleIndex);
        this.indices.put("decoder", this.decoderIndex);

        // Stub getIndexName to prevent NPE in logic: type = indexName.substring(indexName.lastIndexOf('-') + 1)
        when(this.ruleIndex.getIndexName()).thenReturn(".wazuh-rule");
        when(this.decoderIndex.getIndexName()).thenReturn(".wazuh-decoder");

        // Mock Client execution for SAP actions (void return or ignored return)
        when(this.client.execute(any(), any())).thenReturn(this.actionFuture);

        // Mock Client get() for the Update logic (fetching the updated document)
        when(this.client.get(any(GetRequest.class))).thenReturn(this.getResponseFuture);
        when(this.getResponseFuture.actionGet()).thenReturn(this.getResponse);

        this.updateService = new UpdateServiceImpl(CONTEXT, CONSUMER, this.apiClient, this.consumersIndex, this.indices, this.client, this.securityAnalyticsService);
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
     * Tests a successful update flow containing CREATE, UPDATE, and DELETE operations.
     */
    public void testUpdate_Success() throws Exception {
        // Response
        String changesJson = "{\n" +
            "  \"data\": [\n" +
            "    {\n" +
            "      \"offset\": 10,\n" +
            "      \"resource\": \"rule-1\",\n" +
            "      \"type\": \"CREATE\",\n" +
            "      \"payload\": { \"type\": \"rule\", \"id\": \"rule-1\", \"name\": \"Rule One\" }\n" +
            "    },\n" +
            "    {\n" +
            "      \"offset\": 11,\n" +
            "      \"resource\": \"rule-2\",\n" +
            "      \"type\": \"UPDATE\",\n" +
            "      \"operations\": [ { \"op\": \"replace\", \"path\": \"/name\", \"value\": \"Updated Rule\" } ]\n" +
            "    },\n" +
            "    {\n" +
            "      \"offset\": 12,\n" +
            "      \"resource\": \"decoder-1\",\n" +
            "      \"type\": \"DELETE\"\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        // Mock API response
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
            .thenReturn(SimpleHttpResponse.create(200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        // Mock ContentIndex existence checks
        when(this.ruleIndex.exists("rule-2")).thenReturn(true);
        when(this.decoderIndex.exists("decoder-1")).thenReturn(true);

        // Mock Consumer state retrieval
        when(this.consumersIndex.getConsumer(CONTEXT, CONSUMER)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        // Note: usage of getResponse is overloaded in this test (used for both Consumer check and Client.get() result).
        // Since we don't strictly assert the JSON passed to syncToSap for the UPDATE case in this test,
        // returning the consumer JSON here is acceptable to pass the "isExists" checks.
        when(this.getResponse.getSourceAsString()).thenReturn("{\"local_offset\": 9, \"remote_offset\": 100, \"snapshot_link\": \"http://snap\"}");

        // Act
        this.updateService.update(9, 12);

        // Assert
        // Verify CREATE
        verify(this.ruleIndex).create(eq("rule-1"), any(JsonObject.class));

        // Verify delegation to SAP service (called twice: once for CREATE, once for UPDATE)
        verify(this.securityAnalyticsService, times(2)).upsertRule(any(JsonObject.class));

        // Verify UPDATE
        verify(this.ruleIndex).update(eq("rule-2"), any(List.class));

        // Verify DELETE
        verify(this.decoderIndex).delete("decoder-1");

        // Verify Consumer State Update
        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());

        LocalConsumer updated = consumerCaptor.getValue();
        assertEquals(12, updated.getLocalOffset());
        assertEquals(CONSUMER, updated.getName());
    }

    /**
     * Tests that "policy" resources are skipped but the offset is still tracked.
     */
    public void testUpdate_SkipPolicy() throws Exception {
        // Response
        String changesJson = "{\n" +
            "  \"data\": [\n" +
            "    {\n" +
            "      \"offset\": 20,\n" +
            "      \"resource\": \"policy-1\",\n" +
            "      \"type\": \"CREATE\",\n" +
            "      \"payload\": { \"type\": \"policy\", \"content\": \"...\" }\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
            .thenReturn(SimpleHttpResponse.create(200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        // Mock
        when(this.consumersIndex.getConsumer(CONTEXT, CONSUMER)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(false);

        // Act
        this.updateService.update(19, 20);

        // Assert
        verify(this.ruleIndex, never()).create(anyString(), any());
        verify(this.decoderIndex, never()).create(anyString(), any());

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());
        assertEquals(20, consumerCaptor.getValue().getLocalOffset());
    }

    /**
     * Tests handling of API failures.
     */
    public void testUpdate_ApiFailure() throws Exception {
        // Mock
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
            .thenReturn(SimpleHttpResponse.create(500, "Internal Error", ContentType.TEXT_PLAIN));

        // Act
        this.updateService.update(1, 5);

        // Assert
        verify(this.ruleIndex, never()).create(anyString(), any());
        verify(this.consumersIndex, never()).setConsumer(any());
    }

    /**
     * Tests that the consumer state is reset to 0 if an exception occurs during processing.
     */
    public void testUpdate_ExceptionResetsConsumer() throws Exception {
        // Response
        String changesJson = "{\n" +
            "  \"data\": [\n" +
            "    {\n" +
            "      \"offset\": 30,\n" +
            "      \"resource\": \"rule-bad\",\n" +
            "      \"type\": \"CREATE\",\n" +
            "      \"payload\": { \"type\": \"rule\" }\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        // Mock
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
            .thenReturn(SimpleHttpResponse.create(200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        doThrow(new RuntimeException("Simulated Indexing Failure"))
            .when(this.ruleIndex).create(anyString(), any());

        // Act
        this.updateService.update(29, 30);

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());

        LocalConsumer resetConsumer = consumerCaptor.getValue();
        assertEquals(0, resetConsumer.getLocalOffset());
        assertEquals(CONSUMER, resetConsumer.getName());
    }

    /**
     * Tests CREATE operation when the 'type' in payload doesn't map to any known index.
     */
    public void testUpdate_UnknownType_Create() throws Exception {
        // Response
        String changesJson = "{\n" +
            "  \"data\": [\n" +
            "    {\n" +
            "      \"offset\": 40,\n" +
            "      \"resource\": \"unknown-1\",\n" +
            "      \"type\": \"CREATE\",\n" +
            "      \"payload\": { \"type\": \"unknown_thing\", \"data\": \"...\" }\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        // Mock
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
            .thenReturn(SimpleHttpResponse.create(200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.consumersIndex.getConsumer(CONTEXT, CONSUMER)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn("{}");

        // Act
        this.updateService.update(39, 40);

        // Assert
        verify(this.ruleIndex, never()).create(anyString(), any());
        verify(this.decoderIndex, never()).create(anyString(), any());

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
        assertEquals(40, captor.getValue().getLocalOffset());
    }

    /**
     * Tests UPDATE/DELETE operation when the resource ID is not found in any index.
     */
    public void testUpdate_ResourceNotFound() throws Exception {
        // Response
        String changesJson = "{\n" +
            "  \"data\": [\n" +
            "    {\n" +
            "      \"offset\": 50,\n" +
            "      \"resource\": \"fake-id\",\n" +
            "      \"type\": \"DELETE\"\n" +
            "    }\n" +
            "  ]\n" +
            "}";

        // Mock
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
            .thenReturn(SimpleHttpResponse.create(200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.ruleIndex.exists("fake-id")).thenReturn(false);
        when(this.decoderIndex.exists("fake-id")).thenReturn(false);

        when(this.consumersIndex.getConsumer(CONTEXT, CONSUMER)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn("{}");

        // Act
        this.updateService.update(49, 50);

        // Assert
        verify(this.ruleIndex, never()).delete(anyString());
        verify(this.decoderIndex, never()).delete(anyString());

        verify(this.consumersIndex).setConsumer(any(LocalConsumer.class));
    }
}
