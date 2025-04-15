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
package com.wazuh.contentmanager.utils;

import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.nio.file.Path;

import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import org.mockito.ArgumentCaptor;
import org.mockito.Mockito;

import static org.mockito.Mockito.*;

/** Class to handle unzip tests */
public class SnapshotHelperTests extends OpenSearchTestCase {

    SnapshotHelper snapshotHelper;
    private Appender mockAppender;
    private ArgumentCaptor<LogEvent> logEventArgumentCaptor;
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        Path tempDir = createTempDir();
        Settings settings =
                Settings.builder()
                        .put("path.home", tempDir.toString()) // Required by OpenSearch
                        .putList("path.repo", tempDir.toString())
                        .build();
        Environment environment = new Environment(settings, tempDir);
        contextIndex = mock(ContextIndex.class);
        contentIndex = mock(ContentIndex.class);
        ConsumerInfo consumerInfo = mock(ConsumerInfo.class);
        snapshotHelper =
                Mockito.spy(
                        new SnapshotHelper(environment, contextIndex, contentIndex) {
                            @Override
                            protected ConsumerInfo getConsumerInfo() {
                                return consumerInfo;
                            }
                        });
        mockAppender = mock(Appender.class);
        logEventArgumentCaptor = ArgumentCaptor.forClass(LogEvent.class);
        when(mockAppender.getName()).thenReturn("MockAppender");
        when(mockAppender.isStarted()).thenReturn(true);
        final Logger logger = (Logger) LogManager.getLogger(SnapshotHelper.class);
        logger.addAppender(mockAppender);
        logger.setLevel(Level.DEBUG);
    }

    /**
     * Tests an IOException updating the context index will stop the update from snapshot
     *
     * @throws IOException Mocked from updateContextIndex()
     */
    public void testContentIndexFailsUpdating() throws IOException {
        doThrow(new IOException()).when(snapshotHelper).updateContextIndex();
        snapshotHelper.initializeCVEIndex();
        verify(mockAppender, times(1)).append(logEventArgumentCaptor.capture());
        assertTrue(
                logEventArgumentCaptor
                        .getValue()
                        .getMessage()
                        .getFormattedMessage()
                        .contains("Failed to initialize CVE Index from snapshot:"));
    }

    public void testSuccessfulConsumerIndexing() throws IOException {
        when(consumerInfo.getContext()).thenReturn("test-context");

        IndexResponse response = mock(IndexResponse.class);
        when(response.getResult()).thenReturn(DocWriteResponse.Result.CREATED);

        when(contextIndex.index(consumerInfo)).thenReturn(response);
        snapshotHelper.updateContextIndex();
        verify(contextIndex).index(consumerInfo);
    }

    public void testContentSnapshotfailsindexing() throws IOException {
        doThrow(new IOException()).when(snapshotHelper).updateContextIndex();
        snapshotHelper.initializeCVEIndex();
        verify(mockAppender, times(1)).append(logEventArgumentCaptor.capture());
        assertTrue(
                logEventArgumentCaptor
                        .getValue()
                        .getMessage()
                        .getFormattedMessage()
                        .contains("Failed to initialize CVE Index from snapshot:"));
    }

    @SuppressWarnings("EmptyMethod")
    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }
}
