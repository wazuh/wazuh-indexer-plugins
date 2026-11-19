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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link UpdateServiceImpl} class. This test suite validates the incremental
 * update service responsible for applying catalog changes via offset-based synchronization.
 *
 * <p>Tests cover offset retrieval, application of create/update/delete operations via JSON Patch,
 * consumer offset tracking, handling of missing documents, and proper error recovery. Mock objects
 * simulate API client interactions and OpenSearch operations to test update logic in isolation.
 */
public class UpdateServiceImplTests extends OpenSearchTestCase {

    private UpdateServiceImpl updateService;
    private AutoCloseable closeable;

    @Mock private ApiClient apiClient;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private ContentIndex ruleIndex;
    @Mock private ContentIndex decoderIndex;
    @Mock private ContentIndex cveIndex;
    @Mock private ContentIndex integrationIndex;
    @Mock private GetResponse getResponse;

    private static final String CONTEXT = "rules_dev";
    private static final String CONSUMER = "test_consumer";
    private static final String CONSUMER_TYPE = "cti:catalog:consumer:ruleset";
    private static final String CONSUMER_URI =
            "https://api.pre.cloud.wazuh.com/api/v1/catalog/contexts/rules_dev/consumers/test_consumer";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);

        PluginSettings.getInstance(Settings.EMPTY);

        Map<String, ContentIndex> indices = new HashMap<>();
        indices.put("rule", this.ruleIndex);
        indices.put("decoder", this.decoderIndex);
        indices.put("cves", this.cveIndex);
        indices.put(Constants.KEY_INTEGRATION, this.integrationIndex);

        this.updateService =
                new UpdateServiceImpl(
                        CONTEXT,
                        CONSUMER,
                        CONSUMER_TYPE,
                        CONSUMER_URI,
                        this.apiClient,
                        this.consumersIndex,
                        indices);

        // ContentIndex.create is now asynchronous; make the mocks complete their listener so the
        // service's blocking bridge does not time out.
        for (ContentIndex index : indices.values()) {
            lenient()
                    .doAnswer(
                            invocation -> {
                                ActionListener<IndexResponse> listener = invocation.getArgument(2);
                                listener.onResponse(null);
                                return null;
                            })
                    .when(index)
                    .create(anyString(), any(JsonNode.class), any());
            lenient()
                    .doAnswer(
                            invocation -> {
                                ActionListener<IndexResponse> listener = invocation.getArgument(2);
                                listener.onResponse(null);
                                return null;
                            })
                    .when(index)
                    .create(anyString(), any(JsonNode.class), any(), any());
        }
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
     *
     * @throws Exception
     */
    public void testUpdate_Success() throws Exception {
        // Response
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 10,
                      "resource": "rule-1",
                      "type": "CREATE",
                      "payload": { "type": "rule", "id": "rule-1", "name": "Rule One" }
                    },
                    {
                      "offset": 11,
                      "resource": "rule-2",
                      "type": "UPDATE",
                      "operations": [ { "op": "replace", "path": "/name", "value": "Updated Rule" } ]
                    },
                    {
                      "offset": 12,
                      "resource": "decoder-1",
                      "type": "DELETE"
                    }
                  ]
                }""";
        // spotless:on

        // Mock
        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.ruleIndex.exists("rule-2")).thenReturn(true);
        when(this.decoderIndex.exists("decoder-1")).thenReturn(true);

        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString())
                .thenReturn(
                        "{\"name\":\"public-ruleset-5\",\"context\":\"t1-ruleset-5\","
                                + "\"type\":\"cti:catalog:consumer:ruleset\","
                                + "\"resource\":\"https://cti.example/api/v1/catalog/contexts/t1-ruleset-5/consumers/public-ruleset-5\","
                                + "\"is_public\":false,"
                                + "\"local_offset\":9,\"remote_offset\":100,"
                                + "\"updated_at\":\"2026-10-20T08:00:00.123Z\"}");

        // Act
        boolean result = this.updateService.update(9, 12);

        // Assert
        Assert.assertTrue("update() should return true on success", result);
        // Verify CREATE
        verify(this.ruleIndex).create(eq("rule-1"), any(JsonNode.class), any(), any());

        // Verify UPDATE (offset is now passed as the third argument)
        verify(this.ruleIndex).update(eq("rule-2"), any(List.class), any());

        // Verify DELETE
        verify(this.decoderIndex).delete("decoder-1");

        // Verify Consumer State Update
        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture(), eq(true));

        LocalConsumer updated = consumerCaptor.getValue();
        Assert.assertEquals(12, updated.getLocalOffset());
        Assert.assertEquals(12, updated.getRemoteOffset());
        Assert.assertEquals("public-ruleset-5", updated.getName());
        Assert.assertEquals("t1-ruleset-5", updated.getContext());
        Assert.assertEquals(
                "https://cti.example/api/v1/catalog/contexts/t1-ruleset-5/consumers/public-ruleset-5",
                updated.getResource());
        // The pass that runs the update records the new time once it completes.
        Assert.assertEquals("2026-10-20T08:00:00.123Z", updated.getUpdatedAt());
    }

    /**
     * Tests that no consumer state is written when the first batch fails before any checkpoint.
     *
     * @throws Exception
     */
    public void testUpdate_ExceptionDoesNotWriteConsumerState() throws Exception {
        // Response
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 30,
                      "resource": "rule-bad",
                      "type": "CREATE",
                      "payload": { "type": "rule" }
                    }
                  ]
                }""";
        // spotless:on

        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        doThrow(new RuntimeException("Simulated Indexing Failure"))
                .when(this.ruleIndex)
                .create(anyString(), any(JsonNode.class), any(), any());

        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString())
                .thenReturn(
                        "{\"name\":\"public-ruleset-5\",\"context\":\"t1-ruleset-5\","
                                + "\"type\":\"cti:catalog:consumer:ruleset\","
                                + "\"resource\":\"https://cti.example/api/v1/catalog/contexts/t1-ruleset-5/consumers/public-ruleset-5\","
                                + "\"is_public\":true,"
                                + "\"local_offset\":29,\"remote_offset\":100}");

        // Act
        LuceneTestCase.expectThrows(RuntimeException.class, () -> this.updateService.update(29, 30));

        // Assert — no checkpoint written because the batch failed before completing
        verify(this.consumersIndex, never()).setConsumer(any(LocalConsumer.class), anyBoolean());
    }

    /**
     * Tests that "policy" resources are skipped but the offset is still tracked.
     *
     * @throws Exception
     */
    public void testUpdate_SkipPolicy() throws Exception {
        // Response
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 20,
                      "resource": "policy-1",
                      "type": "CREATE",
                      "payload": { "type": "policy", "content": "..." }
                    }
                  ]
                }""";
        // spotless:on

        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        // Mock
        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(false);

        // Act
        boolean result = this.updateService.update(19, 20);

        // Assert
        Assert.assertTrue("update() should return true on success", result);
        verify(this.ruleIndex, never()).create(anyString(), any(JsonNode.class), any(), any());
        verify(this.decoderIndex, never()).create(anyString(), any(JsonNode.class), any(), any());

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture(), eq(true));
        Assert.assertEquals(20, consumerCaptor.getValue().getLocalOffset());
    }

    /**
     * Tests handling of API failures.
     *
     * @throws Exception
     */
    public void testUpdate_ApiFailure() throws Exception {
        // Mock
        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(SimpleHttpResponse.create(500, "Internal Error", ContentType.TEXT_PLAIN));

        // Act
        LuceneTestCase.expectThrows(RuntimeException.class, () -> this.updateService.update(1, 5));

        // Assert — no checkpoint written because no batch completed
        verify(this.ruleIndex, never()).create(anyString(), any(JsonNode.class), any(), any());
        verify(this.consumersIndex, never()).setConsumer(any(LocalConsumer.class), anyBoolean());
    }

    /**
     * Tests that an exception during processing does not write consumer state when no batch
     * completed.
     *
     * @throws Exception
     */
    public void testUpdate_ExceptionPreservesExistingConsumerState() throws Exception {
        // Response
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 30,
                      "resource": "rule-bad",
                      "type": "CREATE",
                      "payload": { "type": "rule" }
                    }
                  ]
                }""";
        // spotless:on

        // Mock
        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        doThrow(new RuntimeException("Simulated Indexing Failure"))
                .when(this.ruleIndex)
                .create(anyString(), any(JsonNode.class), any(), any());

        // Act
        LuceneTestCase.expectThrows(RuntimeException.class, () -> this.updateService.update(29, 30));

        // Assert — no checkpoint written, existing consumer state is untouched
        verify(this.consumersIndex, never()).setConsumer(any(LocalConsumer.class), anyBoolean());
    }

    /**
     * Tests that partial progress is preserved when a later batch fails.
     *
     * @throws Exception
     */
    public void testUpdate_PartialProgressPreserved() throws Exception {
        // spotless:off
        String batch1Json =
            """
                {
                  "data": [
                    {
                      "offset": 1,
                      "resource": "rule-ok",
                      "type": "CREATE",
                      "payload": { "type": "rule", "id": "rule-ok", "name": "OK" }
                    }
                  ]
                }""";
        // spotless:on

        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, batch1Json.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON))
                .thenReturn(SimpleHttpResponse.create(500, "Internal Error", ContentType.TEXT_PLAIN));

        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(false);

        // Act — range spans 2 batches (0-1000, 1000-1998)
        LuceneTestCase.expectThrows(RuntimeException.class, () -> this.updateService.update(0, 1998));

        // Assert — first batch checkpoint was persisted
        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture(), eq(true));

        LocalConsumer checkpoint = captor.getValue();
        Assert.assertEquals(1000, checkpoint.getLocalOffset());
        Assert.assertEquals(1998, checkpoint.getRemoteOffset());
        Assert.assertEquals(LocalConsumer.Status.RUNNING, checkpoint.getStatus());
    }

    /**
     * Tests CREATE operation when the 'type' in payload doesn't map to any known index.
     *
     * @throws Exception
     */
    public void testUpdate_UnknownType_Create() throws Exception {
        // Response
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 40,
                      "resource": "unknown-1",
                      "type": "CREATE",
                      "payload": { "type": "unknown_thing", "data": "..." }
                    }
                  ]
                }""";
        // spotless:on

        // Mock
        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn("{}");

        // Act
        boolean result = this.updateService.update(39, 40);

        // Assert
        Assert.assertTrue("update() should return true on success", result);
        verify(this.ruleIndex, never()).create(anyString(), any(JsonNode.class), any(), any());
        verify(this.decoderIndex, never()).create(anyString(), any(JsonNode.class), any(), any());

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture(), eq(true));
        Assert.assertEquals(40, captor.getValue().getLocalOffset());
    }

    /**
     * Tests UPDATE/DELETE operation when the resource ID is not found in any index.
     *
     * @throws Exception
     */
    public void testUpdate_ResourceNotFound() throws Exception {
        // Response
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 50,
                      "resource": "fake-id",
                      "type": "DELETE"
                    }
                  ]
                }""";
        // spotless:on

        // Mock
        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.ruleIndex.exists("fake-id")).thenReturn(false);
        when(this.decoderIndex.exists("fake-id")).thenReturn(false);

        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn("{}");

        // Act
        LuceneTestCase.expectThrows(RuntimeException.class, () -> this.updateService.update(49, 50));

        // Assert
        verify(this.ruleIndex, never()).delete(anyString());
        verify(this.decoderIndex, never()).delete(anyString());
    }

    /**
     * Tests that CVE DELETE operations are ignored while offset tracking still advances.
     *
     * @throws Exception if update execution fails.
     */
    public void testUpdate_SkipCveDelete() throws Exception {
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 60,
                      "resource": "CVE-2026-0001",
                      "type": "DELETE"
                    }
                  ]
                }""";
        // spotless:on

        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn("{}");

        boolean result = this.updateService.update(59, 60);

        Assert.assertTrue("update() should return true on success", result);
        verify(this.ruleIndex, never()).delete(anyString());
        verify(this.decoderIndex, never()).delete(anyString());

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture(), eq(true));
        Assert.assertEquals(60, captor.getValue().getLocalOffset());
    }

    /**
     * Tests that non-CVE-prefixed CVE resources are routed to cves and receive derived type.
     *
     * @throws Exception if update execution fails.
     */
    public void testUpdate_MidBatchFailurePersistsCheckpointAtLastSuccessfulOffset()
            throws Exception {
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 101,
                      "resource": "rule-ok",
                      "type": "CREATE",
                      "payload": { "type": "rule", "id": "rule-ok" }
                    },
                    {
                      "offset": 102,
                      "resource": "rule-ok2",
                      "type": "CREATE",
                      "payload": { "type": "rule", "id": "rule-ok2" }
                    },
                    {
                      "offset": 103,
                      "resource": "rule-bad",
                      "type": "CREATE",
                      "payload": { "type": "rule", "id": "rule-bad" }
                    }
                  ]
                }""";
        // spotless:on

        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        // First two creates succeed, third throws
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(2);
                            listener.onResponse(null);
                            return null;
                        })
                .doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(2);
                            listener.onResponse(null);
                            return null;
                        })
                .doThrow(new RuntimeException("Simulated circuit breaker"))
                .when(this.ruleIndex)
                .create(anyString(), any(JsonNode.class), any(), any());

        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString())
                .thenReturn(
                        "{\"name\":\"test\",\"context\":\"rules_dev\","
                                + "\"type\":\"cti:catalog:consumer:ruleset\","
                                + "\"resource\":\"https://cti.example/api\","
                                + "\"is_public\":true,"
                                + "\"local_offset\":100,\"remote_offset\":200,"
                                + "\"updated_at\":\"2026-10-20T08:00:00.123Z\"}");

        LuceneTestCase.expectThrows(RuntimeException.class, () -> this.updateService.update(100, 200));

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture(), eq(true));

        LocalConsumer checkpoint = captor.getValue();
        Assert.assertEquals(102, checkpoint.getLocalOffset());
        Assert.assertEquals(200, checkpoint.getRemoteOffset());
        Assert.assertEquals(LocalConsumer.Status.RUNNING, checkpoint.getStatus());
        Assert.assertEquals("2026-10-20T08:00:00.123Z", checkpoint.getUpdatedAt());
    }

    public void testUpdate_CreateTIdResourceIsIndexedAsCveWithDerivedType() throws Exception {
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 70,
                      "resource": "TID-123",
                      "type": "CREATE",
                      "payload": { "document": { "foo": "bar" } }
                    }
                  ]
                }""";
        // spotless:on

        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn("{}");

        boolean result = this.updateService.update(69, 70);

        Assert.assertTrue("update() should return true on success", result);
        ArgumentCaptor<JsonNode> payloadCaptor = ArgumentCaptor.forClass(JsonNode.class);
        verify(this.cveIndex).create(eq("TID-123"), payloadCaptor.capture(), any(), any());
        Assert.assertEquals("TID", payloadCaptor.getValue().get("type").asText());
        Assert.assertEquals(70L, payloadCaptor.getValue().get("offset").asLong());
    }

    // --- Integration deletions that still list resources (#1818, piece A) ------------------

    /** The DELETE offset of an integration, as CTI sends it: resource id only, no payload. */
    private static final String DELETE_INTEGRATION_CHANGES =
            """
            {
              "data": [
                {
                  "offset": 70,
                  "resource": "integration-1",
                  "type": "DELETE"
                }
              ]
            }""";

    /**
     * Serves {@code changesJson} as the CTI response and wires a consumer document, so a test only
     * has to say what the offsets are.
     */
    private void mockChanges(String changesJson) throws Exception {
        when(this.apiClient.getChanges(anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));
        when(this.consumersIndex.getConsumer(CONSUMER_TYPE)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn("{}");
    }

    /** Stubs the integrations index so {@code integration-1} exists with the given document body. */
    private void mockIntegrationDocument(String documentJson) throws Exception {
        when(this.integrationIndex.getIndexName()).thenReturn(Constants.INDEX_INTEGRATIONS);
        when(this.integrationIndex.exists("integration-1")).thenReturn(true);
        when(this.integrationIndex.getDocument("integration-1"))
                .thenReturn(new ObjectMapper().readTree("{\"document\":" + documentJson + "}"));
    }

    /**
     * An integration whose rules CTI has not unlinked must not be deleted: applying the change would
     * orphan those rules in Security Analytics with nothing left to say who owned them. The offset is
     * rejected and the sync stops there, so the next pass retries from the same place.
     */
    public void testUpdate_DeleteIntegrationStillListingRules_isRejected() throws Exception {
        mockChanges(DELETE_INTEGRATION_CHANGES);
        mockIntegrationDocument(
                "{\"id\":\"integration-1\",\"rules\":[\"rule-a\",\"rule-b\"],"
                        + "\"decoders\":[],\"kvdbs\":[]}");

        RuntimeException thrown =
                Assert.assertThrows(RuntimeException.class, () -> this.updateService.update(69, 70));

        String message = rootCauseMessage(thrown);
        Assert.assertTrue(
                "the failure must name the integration and the resources it still lists, got: " + message,
                message.contains("integration-1") && message.contains("rules"));
        verify(this.integrationIndex, never()).delete(anyString());
    }

    /** Decoders are guarded too, with the same rule as the REST API. */
    public void testUpdate_DeleteIntegrationStillListingDecoders_isRejected() throws Exception {
        mockChanges(DELETE_INTEGRATION_CHANGES);
        mockIntegrationDocument(
                "{\"id\":\"integration-1\",\"rules\":[],\"decoders\":[\"decoder-a\"],\"kvdbs\":[]}");

        RuntimeException thrown =
                Assert.assertThrows(RuntimeException.class, () -> this.updateService.update(69, 70));

        Assert.assertTrue(
                "the failure must name the decoders, got: " + rootCauseMessage(thrown),
                rootCauseMessage(thrown).contains("decoders"));
        verify(this.integrationIndex, never()).delete(anyString());
    }

    /** And KVDBs. */
    public void testUpdate_DeleteIntegrationStillListingKvdbs_isRejected() throws Exception {
        mockChanges(DELETE_INTEGRATION_CHANGES);
        mockIntegrationDocument(
                "{\"id\":\"integration-1\",\"rules\":[],\"decoders\":[],\"kvdbs\":[\"kvdb-a\"]}");

        RuntimeException thrown =
                Assert.assertThrows(RuntimeException.class, () -> this.updateService.update(69, 70));

        Assert.assertTrue(
                "the failure must name the kvdbs, got: " + rootCauseMessage(thrown),
                rootCauseMessage(thrown).contains("kvdbs"));
        verify(this.integrationIndex, never()).delete(anyString());
    }

    /**
     * An integration CTI emptied before deleting is the case the guard is meant to let through: it
     * owns nothing, so nothing is orphaned.
     */
    public void testUpdate_DeleteIntegrationWithNoResources_isApplied() throws Exception {
        mockChanges(DELETE_INTEGRATION_CHANGES);
        mockIntegrationDocument("{\"id\":\"integration-1\",\"rules\":[],\"decoders\":[],\"kvdbs\":[]}");

        Assert.assertTrue("the offset must be applied", this.updateService.update(69, 70));
        verify(this.integrationIndex).delete("integration-1");
    }

    /**
     * The guard only applies to integrations. A rule deletion carries no ownership, so it is applied
     * whatever its document looks like, and the guard must not even read it.
     */
    public void testUpdate_DeleteRule_isNotGuarded() throws Exception {
        // spotless:off
        String changesJson =
            """
                {
                  "data": [
                    {
                      "offset": 71,
                      "resource": "rule-9",
                      "type": "DELETE"
                    }
                  ]
                }""";
        // spotless:on
        mockChanges(changesJson);
        when(this.ruleIndex.exists("rule-9")).thenReturn(true);

        Assert.assertTrue(this.updateService.update(70, 71));
        verify(this.ruleIndex).delete("rule-9");
        verify(this.ruleIndex, never()).getDocument(anyString());
    }

    /**
     * A document the guard cannot read is rejected too. The id was resolved to the integrations index
     * by {@code exists()}, so the document is there and a failed read leaves the guard blind; not
     * knowing whether the integration owns anything is no reason to delete it, because that is the
     * orphaning the guard exists to prevent. The pass stops and the next one reads again.
     */
    public void testUpdate_DeleteIntegrationWithUnreadableDocument_isRejected() throws Exception {
        mockChanges(DELETE_INTEGRATION_CHANGES);
        when(this.integrationIndex.getIndexName()).thenReturn(Constants.INDEX_INTEGRATIONS);
        when(this.integrationIndex.exists("integration-1")).thenReturn(true);
        when(this.integrationIndex.getDocument("integration-1")).thenReturn(null);

        RuntimeException thrown =
                Assert.assertThrows(RuntimeException.class, () -> this.updateService.update(69, 70));

        Assert.assertTrue(
                "the failure must say the document could not be read, got: " + rootCauseMessage(thrown),
                rootCauseMessage(thrown).contains("could not be read"));
        verify(this.integrationIndex, never()).delete(anyString());
    }

    /**
     * An integration whose document carries no resource lists at all owns nothing, so it is deleted.
     * This is the shape the guard must not confuse with a failed read.
     */
    public void testUpdate_DeleteIntegrationWithNoResourceLists_isApplied() throws Exception {
        mockChanges(DELETE_INTEGRATION_CHANGES);
        mockIntegrationDocument("{\"id\":\"integration-1\"}");

        Assert.assertTrue(this.updateService.update(69, 70));
        verify(this.integrationIndex).delete("integration-1");
    }

    /** Unwraps the chain update() wraps a failure in, so a test can assert on the original message. */
    private static String rootCauseMessage(Throwable t) {
        Throwable cause = t;
        while (cause.getCause() != null) {
            cause = cause.getCause();
        }
        return String.valueOf(cause.getMessage());
    }

}
