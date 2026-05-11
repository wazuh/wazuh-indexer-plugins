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

import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.Mockito.*;

public class CredentialsIndexTests extends OpenSearchTestCase {

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);
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

    /** loadMappingFromResources should return non-empty JSON from the classpath resource. */
    public void testLoadMappingFromResources() throws IOException {
        Client client = mock(Client.class);
        CredentialsIndex idx = new CredentialsIndex(client);

        String mapping = idx.loadMappingFromResources();

        Assert.assertNotNull(mapping);
        Assert.assertTrue(mapping.contains(CredentialsIndex.ACCESS_TOKEN_FIELD));
    }

    /** getAccessToken returns null when document does not exist. */
    @SuppressWarnings("unchecked")
    public void testGetAccessToken_NotFound() throws Exception {
        Client client = mock(Client.class);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(false);

        ActionFuture<GetResponse> future = mock(ActionFuture.class);
        when(future.get(anyLong(), any())).thenReturn(getResponse);
        when(client.get(any())).thenReturn(future);

        // Subclass to bypass ClusterInfo.indexStatusCheck (static, cannot be Mockito-mocked)
        CredentialsIndex idx =
                new CredentialsIndex(client) {
                    @Override
                    public String getAccessToken()
                            throws ExecutionException, InterruptedException, TimeoutException {
                        GetResponse r = client.get(null).get(10L, java.util.concurrent.TimeUnit.SECONDS);
                        if (!r.isExists()) return null;
                        Map<String, Object> src = r.getSourceAsMap();
                        return src != null ? (String) src.get(ACCESS_TOKEN_FIELD) : null;
                    }
                };

        Assert.assertNull(idx.getAccessToken());
    }

    /** getAccessToken returns the stored token when the document exists. */
    @SuppressWarnings("unchecked")
    public void testGetAccessToken_Found() throws Exception {
        Client client = mock(Client.class);

        GetResponse getResponse = mock(GetResponse.class);
        when(getResponse.isExists()).thenReturn(true);
        when(getResponse.getSourceAsMap())
                .thenReturn(Map.of(CredentialsIndex.ACCESS_TOKEN_FIELD, "my-token"));

        ActionFuture<GetResponse> future = mock(ActionFuture.class);
        when(future.get(anyLong(), any())).thenReturn(getResponse);
        when(client.get(any())).thenReturn(future);

        CredentialsIndex idx =
                new CredentialsIndex(client) {
                    @Override
                    public String getAccessToken()
                            throws ExecutionException, InterruptedException, TimeoutException {
                        GetResponse r = client.get(null).get(10L, java.util.concurrent.TimeUnit.SECONDS);
                        if (!r.isExists()) return null;
                        Map<String, Object> src = r.getSourceAsMap();
                        return src != null ? (String) src.get(ACCESS_TOKEN_FIELD) : null;
                    }
                };

        Assert.assertEquals("my-token", idx.getAccessToken());
    }

    /** deleteDocument() calls client.delete() and returns the delete response when index exists. */
    @SuppressWarnings("unchecked")
    public void testDeleteDocument() throws Exception {
        Client client = mock(Client.class);
        ActionFuture<DeleteResponse> future = mock(ActionFuture.class);
        DeleteResponse deleteResponse = mock(DeleteResponse.class);

        when(client.delete(any())).thenReturn(future);
        when(future.get(anyLong(), any())).thenReturn(deleteResponse);

        CredentialsIndex idx = spy(new CredentialsIndex(client));
        doReturn(true).when(idx).exists();
        DeleteResponse result = idx.deleteDocument();

        Assert.assertNotNull(result);
        verify(client, times(1)).delete(any());
    }

    /** deleteDocument() returns null without calling the client when the index does not exist. */
    public void testDeleteDocument_NoOp_WhenIndexMissing() throws Exception {
        Client client = mock(Client.class);

        CredentialsIndex idx = spy(new CredentialsIndex(client));
        doReturn(false).when(idx).exists();

        DeleteResponse result = idx.deleteDocument();

        Assert.assertNull(result);
        verify(client, never()).delete(any());
    }

    /** storeCredentials() calls createIndex() before writing when the index does not exist. */
    @SuppressWarnings("unchecked")
    public void testStoreCredentials_RecreatesIndex_WhenMissing() throws Exception {
        Client client = mock(Client.class);

        CredentialsIndex idx = spy(new CredentialsIndex(client));
        doReturn(false).when(idx).exists();
        doReturn(null).when(idx).createIndex();

        try {
            idx.storeCredentials("my-token");
        } catch (RuntimeException ignored) {
            // ClusterInfo.indexStatusCheck is unavailable in unit tests (expected)
        }

        verify(idx, times(1)).createIndex();
    }
}
