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

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.io.IOException;
import java.io.InputStream;
import java.util.Locale;

import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/** Test class for the WazuhRBAC class */
public class WazuhRBACTests extends OpenSearchTestCase {
    @Mock private WazuhRBAC wazuhRBAC;
    @Mock private Client client;

    /** Set up the prerequisites for the tests */
    @Before
    public void setup() {
        client = mock(Client.class);
        wazuhRBAC = Mockito.spy(new WazuhRBAC(client));
    }

    /** Test the case where an RBAC users document is already found */
    public void testInitialize_WhenDocumentExists() {
        doReturn(true).when(wazuhRBAC).documentExists(anyString(), anyString());

        wazuhRBAC.initialize();

        verify(client, never()).index(any(), any());
    }

    /** Test failing to perform a file read */
    public void testInitialize_WhenFileReadFails() {
        doReturn(false).when(wazuhRBAC).documentExists(anyString(), anyString());
        doThrow(new NullPointerException()).when(wazuhRBAC).getResourceAsStream(anyString());
        wazuhRBAC.initialize();
        verify(client, never()).index(any(), any());
    }

    /** Test successful indexing of the document */
    public void testInitialize_SuccessfulIndexing() {
        doReturn(false).when(wazuhRBAC).documentExists(anyString(), anyString());
        // String jsonContent = "{\"user\": \"admin\"}";
        InputStream jsonContent = wazuhRBAC.getResourceAsStream(WazuhRBAC.DEFAULT_USERS_FILENAME);
        ArgumentCaptor<IndexRequest> requestCaptor = ArgumentCaptor.forClass(IndexRequest.class);
        wazuhRBAC.initialize();
        verify(client).index(requestCaptor.capture(), any());
        IndexRequest capturedRequest = requestCaptor.getValue();
        assertEquals(WazuhRBAC.RBAC_INDEX_NAME, capturedRequest.index());
        assertEquals(WazuhRBAC.DEFAULT_USER_ID, capturedRequest.id());
        assertEquals(MediaTypeRegistry.JSON, capturedRequest.getContentType());
        try {
            assertArrayEquals(jsonContent.readAllBytes(), capturedRequest.source().toBytesRef().bytes);
        } catch (IOException | OutOfMemoryError e) {
            fail(String.format(Locale.ROOT, "Exception thrown: %s", e.getMessage()));
        }
    }

    /** Test failure to index the document */
    public void testInitialize_IndexingFails() {
        Appender mockAppender = mock(Appender.class);
        ArgumentCaptor<LogEvent> logEventCaptor = ArgumentCaptor.forClass(LogEvent.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        final Logger logger = (Logger) LogManager.getLogger(WazuhRBAC.class);
        logger.addAppender(mockAppender);
        logger.setLevel(Level.DEBUG);

        doReturn(false).when(wazuhRBAC).documentExists(anyString(), anyString());
        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> listener = invocation.getArgument(1);
                            listener.onFailure(new RuntimeException("Indexing failed"));
                            return null;
                        })
                .when(client)
                .index(any(), any());

        wazuhRBAC.initialize();

        verify(mockAppender, times(1)).append(logEventCaptor.capture());

        final LogEvent logEvent = logEventCaptor.getValue();
        final String logMessage = logEvent.getMessage().getFormattedMessage();
        assertTrue(logMessage.contains("Failed to index"));
    }
}
