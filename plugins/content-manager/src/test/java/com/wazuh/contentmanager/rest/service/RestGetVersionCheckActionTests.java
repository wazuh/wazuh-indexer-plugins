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

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.env.Environment;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.ExecutionException;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestGetVersionCheckAction} class. This test suite validates the REST
 * API endpoint responsible for checking available Wazuh version updates.
 */
public class RestGetVersionCheckActionTests extends OpenSearchTestCase {
    private ApiClient apiClient;
    private RestGetVersionCheckAction action;

    /** Initialize PluginSettings singleton before all tests. */
    @BeforeClass
    public static void setUpClass() {
        try {
            PluginSettings.getInstance(Settings.EMPTY);
        } catch (Exception e) {
            // Already initialized
        }
    }

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.apiClient = mock(ApiClient.class);
    }

    /**
     * Creates a temporary Environment with a VERSION.json containing the given version.
     *
     * @param version the version string to write (e.g., "5.0.0"), or null to skip file creation
     * @return an Environment pointing to the temp directory
     * @throws IOException if writing the file fails
     */
    private Environment createEnvironmentWithVersion(String version) throws IOException {
        Path tempDir = LuceneTestCase.createTempDir();
        if (version != null) {
            String json = "{\"version\": \"" + version + "\"}";
            Files.writeString(tempDir.resolve("VERSION.json"), json, StandardCharsets.UTF_8);
        }
        Settings settings = Settings.builder().put("path.home", tempDir.toString()).build();
        return new Environment(settings, tempDir);
    }

    /**
     * Test successful version check with updates available in all categories. Expected: 200 with
     * last_available_major, last_available_minor, last_available_patch.
     */
    public void testHandleRequest200() throws Exception {
        Environment env = createEnvironmentWithVersion("5.0.0");
        this.action = new RestGetVersionCheckAction(env, this.apiClient);

        // spotless:off
        String ctiResponseBody = "{\"data\":{" +
                "\"major\":[{\"tag\":\"v6.0.0\",\"title\":\"Wazuh v6.0.0\",\"description\":\"Major release\",\"published_date\":\"2026-03-01T10:00:00Z\",\"semver\":{\"major\":6,\"minor\":0,\"patch\":0}}]," +
                "\"minor\":[{\"tag\":\"v5.1.0\",\"title\":\"Wazuh v5.1.0\",\"description\":\"Minor release\",\"published_date\":\"2026-02-15T10:00:00Z\",\"semver\":{\"major\":5,\"minor\":1,\"patch\":0}}]," +
                "\"patch\":[{\"tag\":\"v5.0.1\",\"title\":\"Wazuh v5.0.1\",\"description\":\"Patch release\",\"published_date\":\"2026-01-20T10:00:00Z\",\"semver\":{\"major\":5,\"minor\":0,\"patch\":1}}]" +
                "}}";
        // spotless:on

        SimpleHttpResponse ctiResponse = SimpleHttpResponse.create(200, ctiResponseBody, null);
        when(this.apiClient.getReleaseUpdates("v5.0.0")).thenReturn(ctiResponse);

        BytesRestResponse response = this.action.handleRequest();
        String body = response.content().utf8ToString();

        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertTrue(body.contains("last_available_major"));
        Assert.assertTrue(body.contains("v6.0.0"));
        Assert.assertTrue(body.contains("last_available_minor"));
        Assert.assertTrue(body.contains("v5.1.0"));
        Assert.assertTrue(body.contains("last_available_patch"));
        Assert.assertTrue(body.contains("v5.0.1"));
    }

    /**
     * Test successful version check with empty update arrays. Expected: 200 with empty data object.
     */
    public void testHandleRequest200EmptyArrays() throws Exception {
        Environment env = createEnvironmentWithVersion("5.0.0");
        this.action = new RestGetVersionCheckAction(env, this.apiClient);

        String ctiResponseBody = "{\"data\":{\"major\":[],\"minor\":[],\"patch\":[]}}";
        SimpleHttpResponse ctiResponse = SimpleHttpResponse.create(200, ctiResponseBody, null);
        when(this.apiClient.getReleaseUpdates("v5.0.0")).thenReturn(ctiResponse);

        BytesRestResponse response = this.action.handleRequest();
        String body = response.content().utf8ToString();

        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertFalse(body.contains("last_available_major"));
        Assert.assertFalse(body.contains("last_available_minor"));
        Assert.assertFalse(body.contains("last_available_patch"));
    }

    /** Test when VERSION.json is missing. Expected: 500 with version not found message. */
    public void testHandleRequestVersionNotFound() throws Exception {
        Environment env = createEnvironmentWithVersion(null);
        this.action = new RestGetVersionCheckAction(env, this.apiClient);

        BytesRestResponse response = this.action.handleRequest();
        String body = response.content().utf8ToString();

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
        Assert.assertTrue(body.contains(Constants.E_500_VERSION_NOT_FOUND));
    }

    /** Test when the CTI API returns an error. Expected: error status forwarded. */
    public void testHandleRequestCtiError() throws Exception {
        Environment env = createEnvironmentWithVersion("5.0.0");
        this.action = new RestGetVersionCheckAction(env, this.apiClient);

        String errorBody = "{\"errors\":{\"tag\":[\"is invalid\"]}}";
        SimpleHttpResponse ctiResponse = SimpleHttpResponse.create(400, errorBody, null);
        when(this.apiClient.getReleaseUpdates("v5.0.0")).thenReturn(ctiResponse);

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.BAD_REQUEST, response.status());
    }

    /** Test when the API client throws an exception. Expected: 500. */
    public void testHandleRequestException() throws Exception {
        Environment env = createEnvironmentWithVersion("5.0.0");
        this.action = new RestGetVersionCheckAction(env, this.apiClient);

        when(this.apiClient.getReleaseUpdates(anyString()))
                .thenThrow(new ExecutionException("Connection refused", new RuntimeException()));

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
    }

    /**
     * Test that when multiple releases exist in a category, the last one is returned. Expected: 200
     * with the last release from the array.
     */
    public void testHandleRequestReturnsLastRelease() throws Exception {
        Environment env = createEnvironmentWithVersion("5.0.0");
        this.action = new RestGetVersionCheckAction(env, this.apiClient);

        // spotless:off
        String ctiResponseBody = "{\"data\":{" +
                "\"major\":[]," +
                "\"minor\":[" +
                    "{\"tag\":\"v5.1.0\",\"title\":\"Wazuh v5.1.0\",\"description\":\"First minor\",\"published_date\":\"2026-01-01T00:00:00Z\",\"semver\":{\"major\":5,\"minor\":1,\"patch\":0}}," +
                    "{\"tag\":\"v5.2.0\",\"title\":\"Wazuh v5.2.0\",\"description\":\"Second minor\",\"published_date\":\"2026-02-01T00:00:00Z\",\"semver\":{\"major\":5,\"minor\":2,\"patch\":0}}" +
                "]," +
                "\"patch\":[]" +
                "}}";
        // spotless:on

        SimpleHttpResponse ctiResponse = SimpleHttpResponse.create(200, ctiResponseBody, null);
        when(this.apiClient.getReleaseUpdates("v5.0.0")).thenReturn(ctiResponse);

        BytesRestResponse response = this.action.handleRequest();
        String body = response.content().utf8ToString();

        Assert.assertEquals(RestStatus.OK, response.status());
        Assert.assertTrue(body.contains("v5.2.0"));
        Assert.assertFalse(body.contains("v5.1.0"));
    }
}
