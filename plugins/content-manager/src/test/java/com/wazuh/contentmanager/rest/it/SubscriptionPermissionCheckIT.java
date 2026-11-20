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
package com.wazuh.contentmanager.rest.it;

import org.apache.hc.core5.http.HttpHost;
import org.opensearch.client.Request;
import org.opensearch.client.RequestOptions;
import org.opensearch.client.Response;
import org.opensearch.client.ResponseException;
import org.opensearch.client.RestClient;
import org.opensearch.client.WarningsHandler;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Integration tests for {@code DELETE /_plugins/_content_manager/subscription} with {@code
 * perform_permission_check}.
 *
 * <p>Every subscription request goes to the same node: a node keeps the access token in memory once
 * it registers it, so the cleanup deletion must reach that node too.
 *
 * <p>The stored token is read from {@code .wazuh-internal-state} directly. {@code GET
 * /subscription} can't stand in for that read: it asks the CTI Console for the plan, and a {@code
 * 401} for the invented token deletes the credentials. Under security the index is a protected
 * system index, read with the super-admin certificate.
 *
 * <p>The tests with users that hold or lack the delete permission need the security plugin and run
 * only with {@code -Dsecurity=true}.
 */
public class SubscriptionPermissionCheckIT extends ContentManagerRestTestCase {
    private static final String PERFORM_PERMISSION_CHECK = "perform_permission_check";
    private static final String CREDENTIALS_DOCUMENT = "/.wazuh-internal-state/_doc/credentials";
    private static final String DELETE_ACTION = "cluster:admin/content_manager/subscription/delete";
    private static final String GET_ACTION = "cluster:monitor/content_manager/subscription/get";
    private static final String SECURITY_API = "/_plugins/_security/api/";
    private static final String USER_PASSWORD = "Invented-Passw0rd-1";

    private static final Map<String, Object> ALLOWED =
            Map.of("accessAllowed", true, "missingPrivileges", List.of());

    /** Admin client pinned to one node. */
    private RestClient nodeClient;

    /** Reads the credentials document: the super admin under security, the node client otherwise. */
    private RestClient stateClient;

    private final List<String> createdUsers = new ArrayList<>();

    @Before
    public void setUpClients() throws IOException {
        HttpHost[] node = {this.getClusterHosts().get(0)};
        this.nodeClient = this.buildClient(this.restClientSettings(), node);
        this.stateClient =
                ContentManagerRestTestCase.isSecurityEnabled()
                        ? this.buildSuperAdminClient(node)
                        : this.nodeClient;
    }

    @After
    public void cleanUp() throws IOException {
        try {
            SubscriptionPermissionCheckIT.perform(
                    this.nodeClient, "DELETE", PluginSettings.SUBSCRIPTION_URI, Map.of(), null);
            for (String user : this.createdUsers) {
                SubscriptionPermissionCheckIT.perform(
                        this.nodeClient, "DELETE", SECURITY_API + "rolesmapping/" + user, Map.of(), null);
                SubscriptionPermissionCheckIT.perform(
                        this.nodeClient, "DELETE", SECURITY_API + "internalusers/" + user, Map.of(), null);
                SubscriptionPermissionCheckIT.perform(
                        this.nodeClient, "DELETE", SECURITY_API + "roles/" + user, Map.of(), null);
            }
        } finally {
            this.nodeClient.close();
            if (this.stateClient != this.nodeClient) {
                this.stateClient.close();
            }
        }
    }

    /**
     * A caller that may delete is told so and the token stays stored. Under security the caller is
     * the {@code all_access} admin; without it, the transport action answers on behalf of the missing
     * security plugin. An empty value counts as {@code true}.
     */
    public void testPermissionCheck_allowedCaller_keepsTheStoredToken() throws IOException {
        this.registerToken();

        for (String value : List.of("true", "")) {
            Response response = this.check(this.nodeClient, value);

            assertEquals(200, this.getStatusCode(response));
            assertEquals(ALLOWED, this.parseResponseAsMap(response));
        }
        assertTrue("The permission check removed the stored token", this.isTokenStored());
    }

    /** With {@code false} the request is a real deletion, as without the parameter. */
    public void testPermissionCheckFalse_deletesTheStoredToken() throws IOException {
        this.registerToken();

        Response response = this.check(this.nodeClient, "false");

        assertEquals(200, this.getStatusCode(response));
        assertEquals("Credentials removed", this.parseResponseAsMap(response).get("message"));
        assertFalse("The deletion kept the stored token", this.isTokenStored());
    }

    public void testPermissionCheck_userWithoutDeletePermission_isDenied() throws IOException {
        assumeTrue(
                "Needs the security plugin: run with -Dsecurity=true",
                ContentManagerRestTestCase.isSecurityEnabled());
        this.registerToken();

        try (RestClient reader = this.userClient("cm_subscription_reader", GET_ACTION)) {
            Response response = this.check(reader, "true");

            assertEquals(200, this.getStatusCode(response));
            assertEquals(
                    Map.of("accessAllowed", false, "missingPrivileges", List.of(DELETE_ACTION)),
                    this.parseResponseAsMap(response));
        }
        assertTrue("The permission check removed the stored token", this.isTokenStored());
    }

    public void testPermissionCheck_userWithDeletePermission_isAllowed() throws IOException {
        assumeTrue(
                "Needs the security plugin: run with -Dsecurity=true",
                ContentManagerRestTestCase.isSecurityEnabled());
        this.registerToken();

        try (RestClient deleter = this.userClient("cm_subscription_deleter", DELETE_ACTION)) {
            Response response = this.check(deleter, "true");

            assertEquals(200, this.getStatusCode(response));
            assertEquals(ALLOWED, this.parseResponseAsMap(response));
        }
        assertTrue("The permission check removed the stored token", this.isTokenStored());
    }

    // --- helpers -----------------------------------------------------------------

    private void registerToken() throws IOException {
        Response response =
                SubscriptionPermissionCheckIT.perform(
                        this.nodeClient,
                        "POST",
                        PluginSettings.SUBSCRIPTION_URI,
                        Map.of(),
                        "{\"access_token\":\"an-invented-access-token\"}");
        assertEquals(201, this.getStatusCode(response));
        assertTrue("The registration stored no token", this.isTokenStored());
    }

    private Response check(RestClient client, String value) throws IOException {
        return SubscriptionPermissionCheckIT.perform(
                client,
                "DELETE",
                PluginSettings.SUBSCRIPTION_URI,
                Map.of(PERFORM_PERMISSION_CHECK, value),
                null);
    }

    private boolean isTokenStored() throws IOException {
        try {
            Response response =
                    SubscriptionPermissionCheckIT.perform(
                            this.stateClient, "GET", CREDENTIALS_DOCUMENT, Map.of(), null);
            return Boolean.TRUE.equals(this.parseResponseAsMap(response).get("found"));
        } catch (ResponseException e) {
            if (e.getResponse().getStatusLine().getStatusCode() == 404) {
                return false;
            }
            throw e;
        }
    }

    /**
     * Creates a user whose only role grants the given cluster action, and a client that sends its
     * requests to the pinned node as that user.
     */
    private RestClient userClient(String name, String clusterAction) throws IOException {
        this.createdUsers.add(name);
        SubscriptionPermissionCheckIT.perform(
                this.nodeClient,
                "PUT",
                SECURITY_API + "roles/" + name,
                Map.of(),
                "{\"cluster_permissions\":[\"" + clusterAction + "\"]}");
        SubscriptionPermissionCheckIT.perform(
                this.nodeClient,
                "PUT",
                SECURITY_API + "internalusers/" + name,
                Map.of(),
                "{\"password\":\"" + USER_PASSWORD + "\"}");
        SubscriptionPermissionCheckIT.perform(
                this.nodeClient,
                "PUT",
                SECURITY_API + "rolesmapping/" + name,
                Map.of(),
                "{\"users\":[\"" + name + "\"]}");

        String credentials =
                Base64.getEncoder()
                        .encodeToString((name + ":" + USER_PASSWORD).getBytes(StandardCharsets.UTF_8));
        Settings settings =
                Settings.builder()
                        .put(ThreadContext.PREFIX + ".Authorization", "Basic " + credentials)
                        .build();
        return this.buildClient(settings, new HttpHost[] {this.getClusterHosts().get(0)});
    }

    private static Response perform(
            RestClient client, String method, String endpoint, Map<String, String> params, String body)
            throws IOException {
        Request request = new Request(method, endpoint);
        RequestOptions.Builder options = RequestOptions.DEFAULT.toBuilder();
        options.setWarningsHandler(WarningsHandler.PERMISSIVE);
        request.setOptions(options);
        params.forEach(request::addParameter);
        if (body != null) {
            request.setJsonEntity(body);
        }
        return client.performRequest(request);
    }
}
