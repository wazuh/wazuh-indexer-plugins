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

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
import org.junit.Assert;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
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
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.doThrow;
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
    @Mock private GetResponse getResponse;

    private static final String CONTEXT = "rules_dev";
    private static final String CONSUMER = "test_consumer";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);

        PluginSettings.getInstance(Settings.EMPTY);

        Map<String, ContentIndex> indices = new HashMap<>();
        indices.put("rule", this.ruleIndex);
        indices.put("decoder", this.decoderIndex);

        this.updateService =
                new UpdateServiceImpl(CONTEXT, CONSUMER, this.apiClient, this.consumersIndex, indices);
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
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.ruleIndex.exists("rule-2")).thenReturn(true);
        when(this.decoderIndex.exists("decoder-1")).thenReturn(true);

        when(this.consumersIndex.getConsumer(CONTEXT, CONSUMER)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString())
                .thenReturn(
                        "{\"local_offset\": 9, \"remote_offset\": 100, \"snapshot_link\": \"http://snap\"}");

        // Act
        this.updateService.update(9, 12);

        // Assert
        // Verify CREATE
        verify(this.ruleIndex).create(eq("rule-1"), any(JsonNode.class), eq(false));

        // Verify UPDATE
        verify(this.ruleIndex).update(eq("rule-2"), any(List.class));

        // Verify DELETE
        verify(this.decoderIndex).delete("decoder-1");

        // Verify Consumer State Update
        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());

        LocalConsumer updated = consumerCaptor.getValue();
        Assert.assertEquals(12, updated.getLocalOffset());
        Assert.assertEquals(12, updated.getRemoteOffset());
        Assert.assertEquals(CONSUMER, updated.getName());
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

        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        // Mock
        when(this.consumersIndex.getConsumer(CONTEXT, CONSUMER)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(false);

        // Act
        this.updateService.update(19, 20);

        // Assert
        verify(this.ruleIndex, never()).create(anyString(), any(JsonNode.class), anyBoolean());
        verify(this.decoderIndex, never()).create(anyString(), any(JsonNode.class), anyBoolean());

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());
        Assert.assertEquals(20, consumerCaptor.getValue().getLocalOffset());
    }

    /**
     * Tests handling of API failures.
     *
     * @throws Exception
     */
    public void testUpdate_ApiFailure() throws Exception {
        // Mock
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
                .thenReturn(SimpleHttpResponse.create(500, "Internal Error", ContentType.TEXT_PLAIN));

        // Act
        this.updateService.update(1, 5);

        // Assert
        verify(this.ruleIndex, never()).create(anyString(), any(JsonNode.class), anyBoolean());
        verify(this.consumersIndex, never()).setConsumer(any());
    }

    /**
     * Tests that the consumer state is reset to 0 if an exception occurs during processing.
     *
     * @throws Exception
     */
    public void testUpdate_ExceptionResetsConsumer() throws Exception {
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
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        doThrow(new RuntimeException("Simulated Indexing Failure"))
                .when(this.ruleIndex)
                .create(anyString(), any(JsonNode.class), anyBoolean());

        // Act
        this.updateService.update(29, 30);

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());

        LocalConsumer resetConsumer = consumerCaptor.getValue();
        Assert.assertEquals(0, resetConsumer.getLocalOffset());
        Assert.assertEquals(CONSUMER, resetConsumer.getName());
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
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        when(this.consumersIndex.getConsumer(CONTEXT, CONSUMER)).thenReturn(this.getResponse);
        when(this.getResponse.isExists()).thenReturn(true);
        when(this.getResponse.getSourceAsString()).thenReturn("{}");

        // Act
        this.updateService.update(39, 40);

        // Assert
        verify(this.ruleIndex, never()).create(anyString(), any(JsonNode.class), anyBoolean());
        verify(this.decoderIndex, never()).create(anyString(), any(JsonNode.class), anyBoolean());

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
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
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

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
