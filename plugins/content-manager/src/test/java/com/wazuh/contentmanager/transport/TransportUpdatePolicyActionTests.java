/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.transport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.mockito.ArgumentCaptor;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.UpdatePolicyRequest;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TransportUpdatePolicyAction}'s {@code metadata.date}/{@code
 * metadata.modified} handling: unlike the shared {@code Resource.setCreationTime}/{@code
 * setLastModificationTime} helpers used by other resource types, policy updates merge these fields
 * inline against the existing document rather than through that shared code path.
 */
public class TransportUpdatePolicyActionTests extends OpenSearchTestCase {

    private static final String EXISTING_CREATION_DATE = "2020-01-01T00:00:00.000Z";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Client client;
    private SpaceService spaceService;
    private TransportUpdatePolicyAction action;
    private IndexResponse indexResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);

        this.client = mock(Client.class);
        this.spaceService = mock(SpaceService.class);
        EngineService engineService = mock(EngineService.class);
        this.indexResponse = mock(IndexResponse.class);

        this.action =
                new TransportUpdatePolicyAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        this.spaceService,
                        engineService,
                        this.client);

        when(this.spaceService.getKnownEnrichmentTypes()).thenReturn(Collections.emptySet());
        when(this.spaceService.findDocumentId(any(), any(), any())).thenReturn("draft-doc-id");
        when(this.spaceService.calculateAndUpdate(any())).thenReturn(Collections.emptySet());

        when(this.indexResponse.getId()).thenReturn("draft-doc-id");
        PlainActionFuture<IndexResponse> future = PlainActionFuture.newFuture();
        future.onResponse(this.indexResponse);
        when(this.client.index(any(IndexRequest.class))).thenReturn(future);
    }

    @After
    public void tearDown() throws Exception {
        clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    /** Builds the {@code getPolicy()} return value: a draft policy with a known creation date. */
    private Map<String, Object> currentDraftPolicy() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put(Constants.KEY_DATE, EXISTING_CREATION_DATE);
        metadata.put(Constants.KEY_TITLE, "Existing policy");
        metadata.put(Constants.KEY_AUTHOR, "Wazuh Inc.");
        metadata.put(Constants.KEY_DESCRIPTION, "Existing description");
        metadata.put(Constants.KEY_DOCUMENTATION, "");
        metadata.put(Constants.KEY_REFERENCES, Collections.emptyList());

        Map<String, Object> document = new HashMap<>();
        document.put(Constants.KEY_ID, "policy-doc-id");
        document.put(Constants.KEY_METADATA, metadata);
        document.put(Constants.KEY_INTEGRATIONS, Collections.emptyList());
        document.put(Constants.KEY_FILTERS, Collections.emptyList());

        Map<String, Object> policy = new HashMap<>();
        policy.put(Constants.KEY_DOCUMENT, document);
        return policy;
    }

    private String draftUpdateBody(String modifiedField) {
        String modifiedLine =
                modifiedField == null ? "" : "\"modified\": \"" + modifiedField + "\",";
        return "{"
                + "\"type\": \"policy\","
                + "\"resource\": {"
                + "\"root_decoder\": \"\","
                + "\"integrations\": [],"
                + "\"filters\": [],"
                + "\"enrichments\": [],"
                + "\"enabled\": true,"
                + "\"index_unclassified_events\": false,"
                + "\"index_discarded_events\": false,"
                + "\"metadata\": {"
                + "\"title\": \"Updated policy\","
                + modifiedLine
                + "\"author\": \"Test\","
                + "\"description\": \"Updated description\","
                + "\"documentation\": \"\","
                + "\"references\": []"
                + "}"
                + "}"
                + "}";
    }

    /** Captures the {@code document.metadata} node actually sent to the indexing client. */
    private JsonNode capturedIndexedMetadata() throws Exception {
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture());
        JsonNode source = MAPPER.readTree(captor.getValue().source().utf8ToString());
        return source.path(Constants.KEY_DOCUMENT).path(Constants.KEY_METADATA);
    }

    public void testUpdatePolicy_honorsCallerSuppliedModified() throws Exception {
        when(this.spaceService.getPolicy(com.wazuh.contentmanager.cti.catalog.model.Space.DRAFT.toString()))
                .thenReturn(currentDraftPolicy());

        String callerModified = "2021-05-05T00:00:00.000Z";
        UpdatePolicyRequest request =
                new UpdatePolicyRequest("draft", draftUpdateBody(callerModified));

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    return true;
                                }));

        JsonNode metadata = capturedIndexedMetadata();
        Assert.assertEquals(
                "Caller-supplied 'modified' should be honored",
                callerModified,
                metadata.path(Constants.KEY_MODIFIED).asText());
        Assert.assertEquals(
                "'date' should always be preserved from the existing document, never the request body",
                EXISTING_CREATION_DATE,
                metadata.path(Constants.KEY_DATE).asText());
    }

    public void testUpdatePolicy_generatesModifiedWhenAbsent() throws Exception {
        when(this.spaceService.getPolicy(com.wazuh.contentmanager.cti.catalog.model.Space.DRAFT.toString()))
                .thenReturn(currentDraftPolicy());

        UpdatePolicyRequest request = new UpdatePolicyRequest("draft", draftUpdateBody(null));

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    return true;
                                }));

        JsonNode metadata = capturedIndexedMetadata();
        Assert.assertFalse(
                "'modified' should be generated when absent from the request",
                metadata.path(Constants.KEY_MODIFIED).asText("").isBlank());
        Assert.assertEquals(
                "'date' should always be preserved from the existing document",
                EXISTING_CREATION_DATE,
                metadata.path(Constants.KEY_DATE).asText());
    }
}