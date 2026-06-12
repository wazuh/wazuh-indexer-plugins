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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import com.wazuh.contentmanager.cti.catalog.service.SubscriptionService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.Mockito.*;

public class RestIndexSubscriptionActionTests extends OpenSearchTestCase {
    private SubscriptionService subscriptionService;
    private RestIndexSubscriptionAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        RestIndexSubscriptionActionTests.clearPluginSettingsInstance();
        PluginSettings.getInstance(org.opensearch.common.settings.Settings.EMPTY);
        this.subscriptionService = mock(SubscriptionService.class);
        this.action = new RestIndexSubscriptionAction(this.subscriptionService);
    }

    @After
    public void tearDown() throws Exception {
        RestIndexSubscriptionActionTests.clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    private RestRequest buildRequest(String json) {
        return new FakeRestRequest.Builder(this.xContentRegistry())
                .withContent(new BytesArray(json.getBytes(StandardCharsets.UTF_8)), XContentType.JSON)
                .build();
    }

    /** Valid access_token → 201 with correct message and delegates to register(). */
    public void testPostSubscription201() throws Exception {
        RestRequest request = this.buildRequest("{\"access_token\": \"my-token-abc\"}");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.CREATED.getStatus(), response.getStatus());
        Assert.assertEquals(Constants.S_201_ACCESS_TOKEN_RECEIVED, response.getMessage());
        verify(this.subscriptionService, times(1)).register("my-token-abc");
    }

    /** Missing access_token field → 400 with "Missing [access_token] field." */
    public void testPostSubscription400_MissingField() throws IOException {
        RestRequest request = this.buildRequest("{}");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        String body = response.getMessage();
        Assert.assertTrue(body.contains("Missing [access_token] field."));
    }

    /** access_token present but empty → 400 */
    public void testPostSubscription400_EmptyToken() throws IOException {
        RestRequest request = this.buildRequest("{\"access_token\": \"\"}");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        String body = response.getMessage();
        Assert.assertTrue(body.contains("Missing [access_token] field."));
    }

    /** access_token present but blank (whitespace) → 400 */
    public void testPostSubscription400_BlankToken() throws IOException {
        RestRequest request = this.buildRequest("{\"access_token\": \"   \"}");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
    }

    /** register() throws → 500 */
    public void testPostSubscription500_IndexError() throws Exception {
        RestRequest request = this.buildRequest("{\"access_token\": \"tok\"}");
        doThrow(new RuntimeException("Index not ready")).when(this.subscriptionService).register("tok");

        RestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR.getStatus(), response.getStatus());
    }
}
