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
package com.wazuh.contentmanager.cti.catalog.service;

import com.google.gson.JsonObject;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.ContentType;
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

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

public class UpdateServiceImplTests extends OpenSearchTestCase {

    private UpdateServiceImpl updateService;
    private AutoCloseable closeable;

    @Mock private ApiClient apiClient;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private ContentIndex ruleIndex;
    @Mock private ContentIndex decoderIndex;
    @Mock private GetResponse getResponse;

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

        this.updateService =
                new UpdateServiceImpl(CONTEXT, CONSUMER, apiClient, consumersIndex, indices);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Tests a successful update flow containing CREATE, UPDATE, and DELETE operations. */
    public void testUpdate_Success() throws Exception {
        // Response
        String changesJson =
                "{\n"
                        + "  \"data\": [\n"
                        + "    {\n"
                        + "      \"offset\": 10,\n"
                        + "      \"resource\": \"rule-1\",\n"
                        + "      \"type\": \"CREATE\",\n"
                        + "      \"payload\": { \"type\": \"rule\", \"id\": \"rule-1\", \"name\": \"Rule One\" }\n"
                        + "    },\n"
                        + "    {\n"
                        + "      \"offset\": 11,\n"
                        + "      \"resource\": \"rule-2\",\n"
                        + "      \"type\": \"UPDATE\",\n"
                        + "      \"operations\": [ { \"op\": \"replace\", \"path\": \"/name\", \"value\": \"Updated Rule\" } ]\n"
                        + "    },\n"
                        + "    {\n"
                        + "      \"offset\": 12,\n"
                        + "      \"resource\": \"decoder-1\",\n"
                        + "      \"type\": \"DELETE\"\n"
                        + "    }\n"
                        + "  ]\n"
                        + "}";

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
        verify(this.ruleIndex).create(eq("rule-1"), any(JsonObject.class));

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

    /** Tests that "policy" resources are skipped but the offset is still tracked. */
    public void testUpdate_SkipPolicy() throws Exception {
        // Response
        String changesJson =
                "{\n"
                        + "  \"data\": [\n"
                        + "    {\n"
                        + "      \"offset\": 20,\n"
                        + "      \"resource\": \"policy-1\",\n"
                        + "      \"type\": \"CREATE\",\n"
                        + "      \"payload\": { \"type\": \"policy\", \"content\": \"...\" }\n"
                        + "    }\n"
                        + "  ]\n"
                        + "}";

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
        verify(this.ruleIndex, never()).create(anyString(), any());
        verify(this.decoderIndex, never()).create(anyString(), any());

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());
        assertEquals(20, consumerCaptor.getValue().getLocalOffset());
    }

    /** Tests handling of API failures. */
    public void testUpdate_ApiFailure() throws Exception {
        // Mock
        when(apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
                .thenReturn(SimpleHttpResponse.create(500, "Internal Error", ContentType.TEXT_PLAIN));

        // Act
        updateService.update(1, 5);

        // Assert
        verify(ruleIndex, never()).create(anyString(), any());
        verify(consumersIndex, never()).setConsumer(any());
    }

    /** Tests that the consumer state is reset to 0 if an exception occurs during processing. */
    public void testUpdate_ExceptionResetsConsumer() throws Exception {
        // Response
        String changesJson =
                "{\n"
                        + "  \"data\": [\n"
                        + "    {\n"
                        + "      \"offset\": 30,\n"
                        + "      \"resource\": \"rule-bad\",\n"
                        + "      \"type\": \"CREATE\",\n"
                        + "      \"payload\": { \"type\": \"rule\" }\n"
                        + "    }\n"
                        + "  ]\n"
                        + "}";

        // Mock
        when(this.apiClient.getChanges(anyString(), anyString(), anyLong(), anyLong()))
                .thenReturn(
                        SimpleHttpResponse.create(
                                200, changesJson.getBytes(StandardCharsets.UTF_8), ContentType.APPLICATION_JSON));

        doThrow(new RuntimeException("Simulated Indexing Failure"))
                .when(this.ruleIndex)
                .create(anyString(), any());

        // Act
        this.updateService.update(29, 30);

        ArgumentCaptor<LocalConsumer> consumerCaptor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(consumerCaptor.capture());

        LocalConsumer resetConsumer = consumerCaptor.getValue();
        assertEquals(0, resetConsumer.getLocalOffset());
        assertEquals(CONSUMER, resetConsumer.getName());
    }

    /** Tests CREATE operation when the 'type' in payload doesn't map to any known index. */
    public void testUpdate_UnknownType_Create() throws Exception {
        // Response
        String changesJson =
                "{\n"
                        + "  \"data\": [\n"
                        + "    {\n"
                        + "      \"offset\": 40,\n"
                        + "      \"resource\": \"unknown-1\",\n"
                        + "      \"type\": \"CREATE\",\n"
                        + "      \"payload\": { \"type\": \"unknown_thing\", \"data\": \"...\" }\n"
                        + "    }\n"
                        + "  ]\n"
                        + "}";

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
        verify(this.ruleIndex, never()).create(anyString(), any());
        verify(this.decoderIndex, never()).create(anyString(), any());

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
        assertEquals(40, captor.getValue().getLocalOffset());
    }

    /** Tests UPDATE/DELETE operation when the resource ID is not found in any index. */
    public void testUpdate_ResourceNotFound() throws Exception {
        // Response
        String changesJson =
                "{\n"
                        + "  \"data\": [\n"
                        + "    {\n"
                        + "      \"offset\": 50,\n"
                        + "      \"resource\": \"fake-id\",\n"
                        + "      \"type\": \"DELETE\"\n"
                        + "    }\n"
                        + "  ]\n"
                        + "}";

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
