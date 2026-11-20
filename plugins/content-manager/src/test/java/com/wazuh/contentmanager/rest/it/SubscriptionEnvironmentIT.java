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
package com.wazuh.contentmanager.rest.it;

import com.fasterxml.jackson.databind.JsonNode;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import org.apache.hc.core5.http.HttpHost;
import org.opensearch.client.Request;
import org.opensearch.client.Response;
import org.opensearch.client.RestClient;
import org.opensearch.common.SuppressForbidden;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.BeforeClass;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import com.wazuh.contentmanager.ContentManagerRestTestCase;
import com.wazuh.contentmanager.cti.console.EnvironmentFixtures;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * {@code GET /subscription} on a registered instance passes the CTI Console environment through, on
 * every node.
 *
 * <p>The real CTI Console only knows real registrations, so this test serves a fake one. It runs
 * from the {@code ctiConsoleIntegTest} task, whose cluster sends its CTI Console requests to the
 * port in the {@code tests.cti_console.port} system property.
 */
@SuppressForbidden(reason = "Serves a fake CTI Console with the JDK HTTP server")
public class SubscriptionEnvironmentIT extends ContentManagerRestTestCase {

    /** The only access token the fake CTI Console accepts. */
    private static final String ACCESS_TOKEN = "fake-console-token";

    private static final String OPEN_PLANS =
            "{\"plans\": [{\"name\": \"Open\", \"is_public\": true}]}";

    /** Requests the fake CTI Console received for the environment. */
    private static final AtomicInteger ENVIRONMENT_REQUESTS = new AtomicInteger();

    private static HttpServer console;

    @BeforeClass
    public static void startFakeConsole() throws IOException {
        int port = Integer.parseInt(System.getProperty("tests.cti_console.port"));
        console = HttpServer.create(new InetSocketAddress(InetAddress.getLoopbackAddress(), port), 0);
        console.createContext(
                "/api/v1/platform/environments/me",
                exchange -> {
                    ENVIRONMENT_REQUESTS.incrementAndGet();
                    String authorization = exchange.getRequestHeaders().getFirst("Authorization");
                    if (("Bearer " + ACCESS_TOKEN).equals(authorization)) {
                        SubscriptionEnvironmentIT.respond(exchange, 200, EnvironmentFixtures.REGISTERED);
                    } else {
                        SubscriptionEnvironmentIT.respond(
                                exchange, 401, "{\"error\": \"unauthorized_client\"}");
                    }
                });
        console.createContext(
                "/api/v1/catalog/plans",
                exchange -> SubscriptionEnvironmentIT.respond(exchange, 200, OPEN_PLANS));
        console.start();
    }

    @AfterClass
    public static void stopFakeConsole() {
        if (console != null) {
            console.stop(0);
            console = null;
        }
    }

    private static void respond(HttpExchange exchange, int status, String body) throws IOException {
        byte[] bytes = body.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().set("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length);
        try (OutputStream out = exchange.getResponseBody()) {
            out.write(bytes);
        }
    }

    /** Sends {@code GET /subscription} to one node and returns the {@code message} of the answer. */
    private static JsonNode getSubscription(RestClient node) throws IOException {
        Response response = node.performRequest(new Request("GET", PluginSettings.SUBSCRIPTION_URI));
        Assert.assertEquals(200, response.getStatusLine().getStatusCode());
        return MAPPER.readTree(response.getEntity().getContent()).get("message");
    }

    private static void assertUnregistered(JsonNode message) {
        Assert.assertEquals("Open", message.at("/plan/name").asText());
        Assert.assertTrue(message.at("/plan/is_public").asBoolean());
        Assert.assertFalse(message.get("is_registered").asBoolean());
        Assert.assertFalse(message.has("environment"));
    }

    /**
     * Registers the instance on one node and reads the subscription from every node: each answers
     * with the environment exactly as the CTI Console sent it, after one request to the Console. The
     * instance has no environment before it is registered and after it is unregistered.
     */
    public void testRegisteredInstanceGetsTheEnvironmentOnEveryNode() throws Exception {
        List<RestClient> nodes = new ArrayList<>();
        try {
            for (HttpHost host : this.getClusterHosts()) {
                nodes.add(this.buildClient(this.restClientSettings(), new HttpHost[] {host}));
            }
            RestClient registeringNode = nodes.getFirst();
            SubscriptionEnvironmentIT.assertUnregistered(
                    SubscriptionEnvironmentIT.getSubscription(registeringNode));

            Request register = new Request("POST", PluginSettings.SUBSCRIPTION_URI);
            register.setJsonEntity("{\"access_token\": \"" + ACCESS_TOKEN + "\"}");
            Assert.assertEquals(
                    201, registeringNode.performRequest(register).getStatusLine().getStatusCode());
            try {
                String expected = MAPPER.readTree(EnvironmentFixtures.REGISTERED).toString();
                for (RestClient node : nodes) {
                    int requestsBefore = ENVIRONMENT_REQUESTS.get();

                    JsonNode message = SubscriptionEnvironmentIT.getSubscription(node);

                    Assert.assertEquals(EnvironmentFixtures.PLAN_NAME, message.at("/plan/name").asText());
                    Assert.assertFalse(message.at("/plan/is_public").asBoolean());
                    Assert.assertTrue(message.get("is_registered").asBoolean());
                    Assert.assertTrue("no environment in " + message, message.has("environment"));
                    Assert.assertEquals(expected, message.get("environment").toString());
                    Assert.assertEquals(1, ENVIRONMENT_REQUESTS.get() - requestsBefore);
                }
            } finally {
                Request unregister = new Request("DELETE", PluginSettings.SUBSCRIPTION_URI);
                Assert.assertEquals(
                        200, registeringNode.performRequest(unregister).getStatusLine().getStatusCode());
            }
            SubscriptionEnvironmentIT.assertUnregistered(
                    SubscriptionEnvironmentIT.getSubscription(registeringNode));
        } finally {
            for (RestClient node : nodes) {
                node.close();
            }
        }
    }
}
