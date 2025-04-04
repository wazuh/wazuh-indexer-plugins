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

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;

import static com.wazuh.setup.index.WazuhRBAC.RBAC_INDEX_NAME;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** Test class for the WazuhRBAC class */
public class WazuhRBACTests extends OpenSearchTestCase {
    @Mock private WazuhRBAC wazuhRBAC;
    @Mock private Client client;

    @Before
    public void setup() {
        client = mock(Client.class);
        // wazuhRBAC = Mockito.spy(new WazuhRBAC(client));
        wazuhRBAC = Mockito.spy(new WazuhRBAC(client));
    }

    public void testIndexRBACUsers_WhenDocumentExists() {
        doReturn(true).when(wazuhRBAC).documentExists(anyString(), anyString());

        wazuhRBAC.indexRBACUsers();

        verify(client, never()).index(any(), any());
    }

    public void testIndexRBACUsers_WhenFileReadFails() {
        doReturn(false).when(wazuhRBAC).documentExists(anyString(), anyString());
        doThrow(new NullPointerException()).when(wazuhRBAC).getResourceAsStream(anyString());
        wazuhRBAC.indexRBACUsers();
        verify(client, never()).index(any(), any());
    }

    public void testIndexRBACUsers_SuccessfulIndexing() {
        doReturn(false).when(wazuhRBAC).documentExists(anyString(), anyString());
        // String jsonContent = "{\"user\": \"admin\"}";
        InputStream jsonContent = wazuhRBAC.getResourceAsStream(WazuhRBAC.DEFAULT_USERS_FILENAME);
        ArgumentCaptor<IndexRequest> requestCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        wazuhRBAC.indexRBACUsers();
        verify(client).index(requestCaptor.capture(), any());
        IndexRequest capturedRequest = requestCaptor.getValue();
        assertEquals(RBAC_INDEX_NAME, capturedRequest.index());
        assertEquals("1", capturedRequest.id());
        assertEquals(MediaTypeRegistry.JSON, capturedRequest.getContentType());
        try {
            assertArrayEquals(jsonContent.readAllBytes(), capturedRequest.source().toBytesRef().bytes);
        } catch (IOException | OutOfMemoryError e) {
            fail(String.format("Exception thrown: %s", e.getMessage()));
        }
    }

    public void testIndexRBACUsers_IndexingFails() {
        doReturn(false).when(wazuhRBAC).documentExists(anyString(), anyString());
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(1);
                            listener.onFailure(new RuntimeException("Indexing failed"));
                            return null;
                        })
                .when(client)
                .index(any(), any());

        wazuhRBAC.indexRBACUsers();
    }
}
