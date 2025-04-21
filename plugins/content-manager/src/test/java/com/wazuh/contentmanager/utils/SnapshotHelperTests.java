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

import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;
import org.junit.Test;

import java.io.IOException;
import java.nio.file.Path;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;

import static org.mockito.Mockito.*;

/** Class to handle unzip tests */
public class SnapshotHelperTests extends OpenSearchTestCase {

    private AutoCloseable closeable;
    private ContentIndex contentIndex;
    private CTIClient ctiClient;
    private ContextIndex contextIndex;
    private SnapshotHelper snapshotHelper;
    private Environment environment;

    @Before
    public void setUp() throws Exception {
        super.setUp();
        Path envDir = createTempDir();
        Settings settings =
                Settings.builder()
                        .put("path.home", envDir.toString()) // Required by OpenSearch
                        .putList("path.repo", envDir.toString())
                        .build();

        environment = new Environment(settings, envDir);
        contentIndex = mock(ContentIndex.class);
        contextIndex = mock(ContextIndex.class);
        ctiClient = mock(CTIClient.class);
        snapshotHelper =
                SnapshotHelper.getInstance(
                        this.ctiClient, this.environment, this.contextIndex, this.contentIndex);
    }

    @Test
    public void testSingleton() {
        assertEquals(SnapshotHelper.getInstance(), snapshotHelper);
    }

    @Test
    public void testSuccessfulConsumerIndexing() throws IOException {
        ConsumerInfo consumerInfo =
                new ConsumerInfo("test-name", "test-context", 1L, 1L, "http://example.com");
        doReturn(consumerInfo).when(ctiClient).getCatalog();
        IndexResponse response = mock(IndexResponse.class, "SuccessfulResponse");

        doReturn(response).when(this.contextIndex).index(consumerInfo);
        doReturn(DocWriteResponse.Result.CREATED).when(response).getResult();

        logger.info(response);

        SnapshotHelper.getInstance().updateContextIndex();
        verify(this.contextIndex).index(any(ConsumerInfo.class));
    }

    @Test
    public void testFailedConsumerIndexing() {
        ConsumerInfo consumerInfo =
                new ConsumerInfo("test-name", "test-context", 1L, 1L, "http://example.com");
        doReturn(consumerInfo).when(ctiClient).getCatalog();
        IndexResponse response = mock(IndexResponse.class, "FailedResponse");

        doReturn(response).when(this.contextIndex).index(consumerInfo);
        doReturn(DocWriteResponse.Result.NOT_FOUND).when(response).getResult();

        try {
            SnapshotHelper.getInstance().updateContextIndex();
        } catch (IOException e) {
            return;
        }
        assert (false);
    }
}
