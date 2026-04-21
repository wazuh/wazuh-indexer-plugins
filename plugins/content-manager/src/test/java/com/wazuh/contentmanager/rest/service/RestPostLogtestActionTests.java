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
package com.wazuh.contentmanager.rest.service;

import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.nio.charset.StandardCharsets;
import java.util.Locale;

import com.wazuh.contentmanager.cti.catalog.service.LogtestService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RestPostLogtestAction}. Validates request validation logic: required
 * fields, space constraints, and delegation to {@link LogtestService}.
 */
public class RestPostLogtestActionTests extends OpenSearchTestCase {

    private RestPostLogtestAction action;
    private AutoCloseable closeable;

    @Mock private LogtestService logtestService;

    private static final String INTEGRATION_ID = "a0b448c8-3d3c-47d4-b7b9-cbc3c175f509";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.action = new RestPostLogtestAction(this.logtestService);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    private RestRequest mockRequest(String json) {
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(true);
        when(request.content()).thenReturn(new BytesArray(json.getBytes(StandardCharsets.UTF_8)));
        return request;
    }

    // spotless:off
    private String validRequest() {
        return String.format(Locale.ROOT,
            """
            {
              "integration": "%s",
              "space": "test",
              "queue": 1,
              "location": "/var/log/cassandra/system.log",
              "event": "INFO  [main] 2026-03-31 10:00:00 StorageService.java:123 - Node is ready to serve",
              "trace_level": "NONE"
            }
            """,
            INTEGRATION_ID);
    }
    // spotless:on

    /** Empty payload returns 400. */
    public void testEmptyPayload400() {
        RestRequest request = mock(RestRequest.class);
        when(request.hasContent()).thenReturn(false);
        RestResponse response = this.action.handleRequest(request);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        verify(this.logtestService, never()).executeLogtest(anyString(), any(), any());
    }

    /** Invalid JSON returns 400. */
    public void testInvalidJson400() {
        RestRequest request = mockRequest("{not valid json");
        RestResponse response = this.action.handleRequest(request);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        verify(this.logtestService, never()).executeLogtest(anyString(), any(), any());
    }

    /** Missing space field returns 400. */
    public void testMissingSpace400() {
        // spotless:off
        RestRequest request = mockRequest(
            """
            {"integration": "some-id", "queue": 1, "location": "/var/log/test.log", "event": "test"}
            """
        );
        // spotless:on
        RestResponse response = this.action.handleRequest(request);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("space"));
        verify(this.logtestService, never()).executeLogtest(anyString(), any(), any());
    }

    /** Non-test space returns 400 with appropriate message. */
    public void testNonTestSpace400() {
        // spotless:off
        RestRequest request = mockRequest(
            """
            {"integration": "some-id", "space": "draft", "queue": 1, "event": "test"}
            """
        );
        // spotless:on
        RestResponse response = this.action.handleRequest(request);
        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        Assert.assertTrue(response.getMessage().contains("draft"));
        verify(this.logtestService, never()).executeLogtest(anyString(), any(), any());
    }

    /** Valid request delegates to LogtestService with correct arguments. */
    public void testValidRequestDelegatesToService() {
        RestResponse serviceResponse =
                new RestResponse("{\"normalization\":{}}", RestStatus.OK.getStatus());
        when(this.logtestService.executeLogtest(anyString(), any(), any(ObjectNode.class)))
                .thenReturn(serviceResponse);

        RestRequest request = mockRequest(validRequest());
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.OK.getStatus(), response.getStatus());
        var captor = org.mockito.ArgumentCaptor.forClass(ObjectNode.class);
        verify(this.logtestService).executeLogtest(eq(INTEGRATION_ID), any(), captor.capture());

        // Verify integration field is stripped from engine payload
        ObjectNode payload = captor.getValue();
        Assert.assertFalse(payload.has("integration"));
        Assert.assertTrue(payload.has("space"));
        Assert.assertTrue(payload.has("queue"));
        Assert.assertTrue(payload.has("event"));
    }

    /** Service response is returned as-is. */
    public void testServiceResponsePassedThrough() {
        RestResponse serviceResponse =
                new RestResponse("{\"normalization\":{},\"detection\":{}}", RestStatus.OK.getStatus());
        when(this.logtestService.executeLogtest(anyString(), any(), any(ObjectNode.class)))
                .thenReturn(serviceResponse);

        RestRequest request = mockRequest(validRequest());
        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(serviceResponse, response);
    }
}
