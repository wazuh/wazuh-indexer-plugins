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

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;
import org.apache.logging.log4j.core.Appender;
import org.apache.logging.log4j.core.LogEvent;
import org.apache.logging.log4j.core.Logger;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;
import java.nio.file.Path;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import org.mockito.InjectMocks;
import org.mockito.Mock;

import static org.mockito.Mockito.*;

/** Class to handle unzip tests */
@ThreadLeakScope(ThreadLeakScope.Scope.TEST)
public class SnapshotHelperTests extends OpenSearchTestCase {

    @InjectMocks private SnapshotHelper snapshotHelper;
    @Mock private CTIClient ctiClient;
    @Mock private ContentIndex contentIndex;
    @Mock private ContextIndex contextIndex;
    @Mock private Environment environment;
    //@Mock private Appender mockAppender;
    //private ArgumentCaptor<LogEvent> logEventArgumentCaptor;
    //private Logger logger;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        Path envDir = createTempDir();
        Settings settings =
                Settings.builder()
                        .put("path.home", envDir.toString()) // Required by OpenSearch
                        .putList("path.repo", envDir.toString())
                        .build();

        environment = new Environment(settings, envDir);
        contextIndex = mock(ContextIndex.class);
        contentIndex = mock(ContentIndex.class);
        ctiClient = mock(CTIClient.class);
        snapshotHelper = SnapshotHelper.getInstance(ctiClient, environment, contextIndex, contentIndex);
        //mockAppender = mock(Appender.class);
        //logEventArgumentCaptor = ArgumentCaptor.forClass(LogEvent.class);
        //when(mockAppender.getName()).thenReturn("MockAppender");
        //when(mockAppender.isStarted()).thenReturn(true);
        //logger = (Logger) LogManager.getLogger(SnapshotHelper.class);
        //logger.addAppender(mockAppender);
        //logger.setLevel(Level.DEBUG);
    }

    /**
     * @throws IOException rethrown from updateContextIndex()
     */
    public void testSuccessfulConsumerIndexing() throws IOException {
        ConsumerInfo consumerInfo = mock(ConsumerInfo.class);
        when(ctiClient.getCatalog()).thenReturn(consumerInfo);

        IndexResponse response = mock(IndexResponse.class);

        doReturn(response).when(this.contextIndex).index(any(ConsumerInfo.class));

        doReturn(DocWriteResponse.Result.CREATED).when(response).getResult();

        snapshotHelper.updateContextIndex();
        verify(contextIndex).index(consumerInfo);
    }

    /**
     *
     */
    public void testFailedConsumerIndexing() {
        ConsumerInfo consumerInfo = mock(ConsumerInfo.class);
        when(ctiClient.getCatalog()).thenReturn(consumerInfo);

        IndexResponse response = mock(IndexResponse.class);

        doReturn(response).when(this.contextIndex).index(any(ConsumerInfo.class));

        DocWriteResponse.Result notFound = DocWriteResponse.Result.NOT_FOUND;
        doReturn(notFound).when(response).getResult();
        logger.info(response.getResult());

        try {
            snapshotHelper.updateContextIndex();
        } catch (IOException e) {
            return;
        }
        assert(false);
    }

    ///**
    // * Test fail indexing
    // */
    //public void testContentIndexFailsUpdating() {
    //    ConsumerInfo consumerInfo = mock(ConsumerInfo.class);
    //    IndexResponse response = mock(IndexResponse.class);
    //    when(ctiClient.getCatalog()).thenReturn(consumerInfo);
    //    when(contextIndex.index(consumerInfo)).thenReturn(response);
    //    when(response.getResult()).thenReturn(DocWriteResponse.Result.NOT_FOUND);
    //    snapshotHelper.initializeCVEIndex();
    //    verify(mockAppender).append(logEventArgumentCaptor.capture());
    //    assertTrue(
    //            logEventArgumentCaptor
    //                    .getValue()
    //                    .getMessage()
    //                    .getFormattedMessage()
    //                    .contains("Consumer indexing operation returned with unexpected result"));
    //    logger.removeAppender(mockAppender);
    //}
}
