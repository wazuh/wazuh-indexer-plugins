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
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.charset.StandardCharsets;

import com.wazuh.contentmanager.cti.catalog.index.CredentialsIndex;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.*;

public class RestPostSubscriptionActionTests extends OpenSearchTestCase {
    private CredentialsIndex credentialsIndex;
    private RestPostSubscriptionAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(org.opensearch.common.settings.Settings.EMPTY);
        this.credentialsIndex = mock(CredentialsIndex.class);
        this.action = new RestPostSubscriptionAction(this.credentialsIndex);
    }

    @After
    public void tearDown() throws Exception {
        clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    private RestRequest buildRequest(String json) {
        return new FakeRestRequest.Builder(xContentRegistry())
                .withContent(new BytesArray(json.getBytes(StandardCharsets.UTF_8)), XContentType.JSON)
                .build();
    }

    /** Valid access_token → 201 with "Credentials received" */
    public void testPostCredentials201() throws Exception {
        RestRequest request = buildRequest("{\"access_token\": \"my-token-abc\"}");

        BytesRestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.CREATED, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("Credentials received"));
        Assert.assertTrue(body.contains(String.valueOf(RestStatus.CREATED.getStatus())));

        verify(this.credentialsIndex, times(1)).storeCredentials("my-token-abc");
        Assert.assertEquals("my-token-abc", PluginSettings.getInstance().getAccessToken());
    }

    /** Missing access_token field → 400 with "Missing [access_token] field." */
    public void testPostCredentials400_MissingField() throws IOException {
        RestRequest request = buildRequest("{}");

        BytesRestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("Missing [access_token] field."));
    }

    /** access_token present but empty → 400 */
    public void testPostCredentials400_EmptyToken() throws IOException {
        RestRequest request = buildRequest("{\"access_token\": \"\"}");

        BytesRestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("Missing [access_token] field."));
    }

    /** access_token present but blank (whitespace) → 400 */
    public void testPostCredentials400_BlankToken() throws IOException {
        RestRequest request = buildRequest("{\"access_token\": \"   \"}");

        BytesRestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.status());
    }

    /** Index throws → 500 */
    public void testPostCredentials500_IndexError() throws Exception {
        RestRequest request = buildRequest("{\"access_token\": \"tok\"}");
        doThrow(new RuntimeException("Index not ready"))
                .when(this.credentialsIndex)
                .storeCredentials("tok");

        BytesRestResponse response = this.action.handleRequest(request);

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
    }
}
