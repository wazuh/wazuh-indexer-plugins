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
package com.wazuh.contentmanager.cti.catalog.utils;

import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequestBuilder;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.action.get.GetRequestBuilder;
import org.opensearch.action.get.GetResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.HashMap;
import java.util.Map;

import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/** Tests for the IndexHelper utility class. */
public class IndexHelperTests extends OpenSearchTestCase {

    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private AdminClient adminClient;
    @Mock private IndicesAdminClient indicesAdminClient;
    @Mock private GetRequestBuilder getRequestBuilder;
    @Mock private GetResponse getResponse;
    @Mock private IndicesExistsRequestBuilder indicesExistsRequestBuilder;
    @Mock private IndicesExistsResponse indicesExistsResponse;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    public void testGetDocumentSourceReturnsSourceWhenDocumentExists() {
        Map<String, Object> expectedSource = new HashMap<>();
        expectedSource.put("field", "value");

        when(client.prepareGet(anyString(), anyString())).thenReturn(getRequestBuilder);
        when(getRequestBuilder.get()).thenReturn(getResponse);
        when(getResponse.isExists()).thenReturn(true);
        when(getResponse.getSourceAsMap()).thenReturn(expectedSource);

        Map<String, Object> result = IndexHelper.getDocumentSource(client, "test-index", "doc-id");

        Assert.assertNotNull(result);
        Assert.assertEquals("value", result.get("field"));
    }

    public void testGetDocumentSourceReturnsNullWhenDocumentDoesNotExist() {
        when(client.prepareGet(anyString(), anyString())).thenReturn(getRequestBuilder);
        when(getRequestBuilder.get()).thenReturn(getResponse);
        when(getResponse.isExists()).thenReturn(false);

        Map<String, Object> result = IndexHelper.getDocumentSource(client, "test-index", "doc-id");

        Assert.assertNull(result);
    }

    public void testGetDocumentSourceReturnsNullOnException() {
        when(client.prepareGet(anyString(), anyString()))
                .thenThrow(new RuntimeException("Test exception"));

        Map<String, Object> result = IndexHelper.getDocumentSource(client, "test-index", "doc-id");

        Assert.assertNull(result);
    }

    public void testIndexExistsReturnsTrue() {
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(indicesAdminClient.prepareExists(anyString())).thenReturn(indicesExistsRequestBuilder);
        when(indicesExistsRequestBuilder.get()).thenReturn(indicesExistsResponse);
        when(indicesExistsResponse.isExists()).thenReturn(true);

        boolean result = IndexHelper.indexExists(client, "test-index");

        Assert.assertTrue(result);
    }

    public void testIndexExistsReturnsFalse() {
        when(client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);
        when(indicesAdminClient.prepareExists(anyString())).thenReturn(indicesExistsRequestBuilder);
        when(indicesExistsRequestBuilder.get()).thenReturn(indicesExistsResponse);
        when(indicesExistsResponse.isExists()).thenReturn(false);

        boolean result = IndexHelper.indexExists(client, "test-index");

        Assert.assertFalse(result);
    }

    public void testIndexExistsReturnsFalseOnException() {
        when(client.admin()).thenThrow(new RuntimeException("Test exception"));

        boolean result = IndexHelper.indexExists(client, "test-index");

        Assert.assertFalse(result);
    }
}
