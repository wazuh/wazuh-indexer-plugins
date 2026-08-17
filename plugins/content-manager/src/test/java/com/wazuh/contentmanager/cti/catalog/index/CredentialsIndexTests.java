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
package com.wazuh.contentmanager.cti.catalog.index;

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

public class CredentialsIndexTests extends OpenSearchTestCase {

    private ThreadPool threadPool;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);
        this.threadPool = mock(ThreadPool.class);
        when(this.threadPool.getThreadContext()).thenReturn(new ThreadContext(Settings.EMPTY));
    }

    @After
    public void tearDown() throws Exception {
        clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field f = PluginSettings.class.getDeclaredField("INSTANCE");
        f.setAccessible(true);
        f.set(null, null);
    }

    /** Mocks the async client.admin().indices().exists(request, listener) chain. */
    @SuppressWarnings("unchecked")
    private static void mockIndexExists(Client client, boolean exists) {
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        IndicesExistsResponse existsResponse = mock(IndicesExistsResponse.class);

        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(existsResponse.isExists()).thenReturn(exists);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<IndicesExistsResponse>>getArgument(1)
                                    .onResponse(existsResponse);
                            return null;
                        })
                .when(indicesAdminClient)
                .exists(any(IndicesExistsRequest.class), any());
    }

    /** loadIndexTemplate should pull a non-empty mapping and settings from the classpath resource. */
    public void testLoadIndexTemplate() throws IOException {
        Client client = mock(Client.class);
        CredentialsIndex idx = new CredentialsIndex(client, threadPool);

        CredentialsIndex.IndexTemplateParts template = idx.loadIndexTemplate();

        Assert.assertNotNull(template.mappings);
        Assert.assertTrue(template.mappings.contains(CredentialsIndex.ACCESS_TOKEN_FIELD));
        Assert.assertEquals("true", template.settings.get("index.hidden"));
    }

    /** deleteDocument() calls client.delete() and returns the delete response when index exists. */
    @SuppressWarnings("unchecked")
    public void testDeleteDocument() throws Exception {
        Client client = mock(Client.class);
        DeleteResponse deleteResponse = mock(DeleteResponse.class);

        mockIndexExists(client, true);
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<DeleteResponse>>getArgument(1).onResponse(deleteResponse);
                            return null;
                        })
                .when(client)
                .delete(any(DeleteRequest.class), any());

        CredentialsIndex idx = new CredentialsIndex(client, threadPool);
        AtomicReference<DeleteResponse> result = new AtomicReference<>();
        idx.deleteDocument(ActionListener.wrap(result::set, e -> {}));

        Assert.assertNotNull(result.get());
        ArgumentCaptor<DeleteRequest> captor = ArgumentCaptor.forClass(DeleteRequest.class);
        verify(client, times(1)).delete(captor.capture(), any());
        // Refresh is disabled on this index, so deletes must refresh immediately to avoid stale reads.
        Assert.assertEquals(WriteRequest.RefreshPolicy.IMMEDIATE, captor.getValue().getRefreshPolicy());
    }

    /** deleteDocument() returns null without calling the client when the index does not exist. */
    public void testDeleteDocument_NoOp_WhenIndexMissing() throws Exception {
        Client client = mock(Client.class);

        mockIndexExists(client, false);

        CredentialsIndex idx = new CredentialsIndex(client, threadPool);
        AtomicReference<DeleteResponse> result = new AtomicReference<>();
        idx.deleteDocument(ActionListener.wrap(result::set, e -> {}));

        Assert.assertNull(result.get());
        verify(client, never()).delete(any(DeleteRequest.class), any());
    }
}
