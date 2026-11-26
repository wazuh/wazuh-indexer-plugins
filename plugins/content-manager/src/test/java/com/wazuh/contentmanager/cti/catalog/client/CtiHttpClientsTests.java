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
package com.wazuh.contentmanager.cti.catalog.client;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.ConnectException;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ExecutionException;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.settings.PluginSettingsTests;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Every client that connects to Wazuh CTI must honour the JVM proxy properties ({@code
 * https.proxyHost}, {@code https.proxyPort}, {@code http.nonProxyHosts}, {@code https.proxyUser},
 * {@code https.proxyPassword}). A loopback proxy records the {@code CONNECT} requests it receives
 * and refuses the tunnel, so the CTI host is never resolved nor reached.
 */
public class CtiHttpClientsTests extends OpenSearchTestCase {

    private static final String CTI_HOST = "cti.example.invalid";
    private static final String CONNECT_LINE = "CONNECT " + CTI_HOST + ":443 HTTP/1.1";
    private static final List<String> JVM_PROPERTIES =
            List.of(
                    "https.proxyHost",
                    "https.proxyPort",
                    "https.proxyUser",
                    "https.proxyPassword",
                    "http.nonProxyHosts",
                    "http.agent");

    private final Map<String, String> savedProperties = new HashMap<>();

    @Override
    public void setUp() throws Exception {
        super.setUp();
        for (String key : JVM_PROPERTIES) {
            this.savedProperties.put(key, System.getProperty(key));
        }
        PluginSettingsTests.clearInstance();
        PluginSettings.getInstance(
                Settings.builder()
                        .put("plugins.content_manager.cti.api", "https://" + CTI_HOST + "/api/v1")
                        .build());
    }

    @Override
    public void tearDown() throws Exception {
        this.savedProperties.forEach(CtiHttpClientsTests::setJvmProperty);
        PluginSettingsTests.clearInstance();
        super.tearDown();
    }

    /** The catalog client tunnels through the proxy and gets the proxy's refusal as its response. */
    public void testCatalogClientUsesJvmProxy() throws Exception {
        try (RecordingProxy proxy = new RecordingProxy(null)) {
            proxy.setJvmProperties();
            setJvmProperty("http.agent", "jvm-wide-agent");

            SimpleHttpResponse response;
            try (ApiClient client = new ApiClient()) {
                response =
                        client.getConsumer("https://" + CTI_HOST + "/api/v1/catalog/contexts/c/consumers/k");
            }

            assertEquals(403, response.getCode());
            assertEquals(1, proxy.requests().size());
            assertConnectFromPlugin(proxy.requests().get(0));
        }
    }

    /** The Console client, also the base of the telemetry client, tunnels through the proxy. */
    public void testConsoleClientUsesJvmProxy() throws Exception {
        try (RecordingProxy proxy = new RecordingProxy(null)) {
            proxy.setJvmProperties();
            setJvmProperty("http.agent", "jvm-wide-agent");

            com.wazuh.contentmanager.cti.console.client.ApiClient client =
                    new com.wazuh.contentmanager.cti.console.client.ApiClient();
            SimpleHttpResponse response;
            try {
                response = client.getCatalogPlans();
            } finally {
                client.close();
            }

            assertEquals(403, response.getCode());
            assertEquals(1, proxy.requests().size());
            assertConnectFromPlugin(proxy.requests().get(0));
        }
    }

    /** The snapshot download tunnels through the proxy. */
    public void testSnapshotClientUsesJvmProxy() throws Exception {
        try (RecordingProxy proxy = new RecordingProxy(null)) {
            proxy.setJvmProperties();
            setJvmProperty("http.agent", "jvm-wide-agent");
            Environment environment = mock(Environment.class);
            when(environment.tmpDir()).thenReturn(createTempDir());

            SnapshotClient client = new SnapshotClient(environment, "cti:catalog:consumer:ruleset");

            assertNull(client.downloadFile("https://" + CTI_HOST + "/store/snapshot.zip"));
            assertEquals(1, proxy.requests().size());
            assertConnectFromPlugin(proxy.requests().get(0));
        }
    }

    /** A proxy that asks for credentials gets the ones set in https.proxyUser/https.proxyPassword. */
    public void testProxyCredentialsFromJvmProperties() throws Exception {
        try (RecordingProxy proxy = new RecordingProxy("cti-user:p@ss:w0rd")) {
            proxy.setJvmProperties();
            setJvmProperty("https.proxyUser", "cti-user");
            setJvmProperty("https.proxyPassword", "p@ss:w0rd");

            SimpleHttpResponse response;
            try (ApiClient client = new ApiClient()) {
                response =
                        client.getConsumer("https://" + CTI_HOST + "/api/v1/catalog/contexts/c/consumers/k");
            }

            assertEquals(403, response.getCode());
            assertEquals(2, proxy.requests().size());
            assertNull(header(proxy.requests().get(0), "Proxy-Authorization"));
            assertEquals(
                    basic("cti-user:p@ss:w0rd"), header(proxy.requests().get(1), "Proxy-Authorization"));
        }
    }

    /** The snapshot download, on the classic client, also answers the proxy's challenge. */
    public void testSnapshotClientSendsProxyCredentials() throws Exception {
        try (RecordingProxy proxy = new RecordingProxy("cti-user:p@ss:w0rd")) {
            proxy.setJvmProperties();
            setJvmProperty("https.proxyUser", "cti-user");
            setJvmProperty("https.proxyPassword", "p@ss:w0rd");
            Environment environment = mock(Environment.class);
            when(environment.tmpDir()).thenReturn(createTempDir());

            SnapshotClient client = new SnapshotClient(environment, "cti:catalog:consumer:ruleset");

            assertNull(client.downloadFile("https://" + CTI_HOST + "/store/snapshot.zip"));
            assertEquals(2, proxy.requests().size());
            assertNull(header(proxy.requests().get(0), "Proxy-Authorization"));
            assertEquals(
                    basic("cti-user:p@ss:w0rd"), header(proxy.requests().get(1), "Proxy-Authorization"));
        }
    }

    /**
     * Credentials the proxy rejects are sent once: the second 407 is returned to the caller, which
     * logs it, instead of looping on the challenge.
     */
    public void testRejectedProxyCredentialsReturnThe407() throws Exception {
        try (RecordingProxy proxy = new RecordingProxy("cti-user:p@ss:w0rd")) {
            proxy.setJvmProperties();
            setJvmProperty("https.proxyUser", "cti-user");
            setJvmProperty("https.proxyPassword", "wrong-password");

            SimpleHttpResponse response;
            try (ApiClient client = new ApiClient()) {
                response =
                        client.getConsumer("https://" + CTI_HOST + "/api/v1/catalog/contexts/c/consumers/k");
            }

            assertEquals(407, response.getCode());
            assertEquals(2, proxy.requests().size());
            assertEquals(
                    basic("cti-user:wrong-password"), header(proxy.requests().get(1), "Proxy-Authorization"));
        }
    }

    /**
     * When the proxy can't be reached, the request fails on the proxy address. It never falls back to
     * a direct connection, which would fail to resolve the CTI host instead.
     */
    public void testUnreachableProxyIsNotBypassed() throws Exception {
        int closedPort = closedLoopbackPort();
        setJvmProperty("https.proxyHost", "127.0.0.1");
        setJvmProperty("https.proxyPort", String.valueOf(closedPort));

        com.wazuh.contentmanager.cti.console.client.ApiClient client =
                new com.wazuh.contentmanager.cti.console.client.ApiClient();
        ExecutionException e;
        try {
            e = expectThrows(ExecutionException.class, client::getCatalogPlans);
        } finally {
            client.close();
        }

        assertTrue(e.getCause().toString(), e.getCause() instanceof ConnectException);
    }

    /** Without the proxy properties, the clients connect directly, as before. */
    public void testNoProxyPropertiesConnectDirectly() throws Exception {
        int closedPort = closedLoopbackPort();
        setJvmProperty("https.proxyHost", null);
        setJvmProperty("https.proxyPort", null);
        PluginSettingsTests.clearInstance();
        PluginSettings.getInstance(
                Settings.builder()
                        .put("plugins.content_manager.cti.api", "https://127.0.0.1:" + closedPort + "/api/v1")
                        .build());

        com.wazuh.contentmanager.cti.console.client.ApiClient client =
                new com.wazuh.contentmanager.cti.console.client.ApiClient();
        ExecutionException e;
        try {
            e = expectThrows(ExecutionException.class, client::getCatalogPlans);
        } finally {
            client.close();
        }

        assertTrue(e.getCause().toString(), e.getCause() instanceof ConnectException);
    }

    /**
     * A host listed in http.nonProxyHosts is connected to directly. The host is a closed loopback
     * port: the direct connection is refused, while through the proxy the call would get a 403.
     */
    public void testNonProxyHostsAreReachedDirectly() throws Exception {
        int closedPort = closedLoopbackPort();
        try (RecordingProxy proxy = new RecordingProxy(null)) {
            proxy.setJvmProperties();
            setJvmProperty("http.nonProxyHosts", "127.0.0.1");
            PluginSettingsTests.clearInstance();
            PluginSettings.getInstance(
                    Settings.builder()
                            .put("plugins.content_manager.cti.api", "https://127.0.0.1:" + closedPort + "/api/v1")
                            .build());

            com.wazuh.contentmanager.cti.console.client.ApiClient client =
                    new com.wazuh.contentmanager.cti.console.client.ApiClient();
            ExecutionException e;
            try {
                e = expectThrows(ExecutionException.class, client::getCatalogPlans);
            } finally {
                client.close();
            }

            assertTrue(e.getCause().toString(), e.getCause() instanceof ConnectException);
            assertEquals(0, proxy.requests().size());
        }
    }

    /** Sets a JVM property, or clears it when {@code value} is null. */
    @SuppressForbidden(reason = "The tests exercise the JVM proxy properties; tearDown restores them")
    private static void setJvmProperty(String key, String value) {
        if (value == null) {
            System.clearProperty(key);
        } else {
            System.setProperty(key, value);
        }
    }

    /** A loopback port nothing listens on: connecting to it is refused at once. */
    private static int closedLoopbackPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0, 1, InetAddress.getLoopbackAddress())) {
            return socket.getLocalPort();
        }
    }

    /** Value of a Basic Proxy-Authorization header for the given {@code user:password}. */
    private static String basic(String credentials) {
        return "Basic "
                + Base64.getEncoder().encodeToString(credentials.getBytes(StandardCharsets.UTF_8));
    }

    /** The request is a CONNECT to the CTI host, identified with the plugin's User-Agent. */
    private static void assertConnectFromPlugin(List<String> request) {
        assertEquals(CONNECT_LINE, request.get(0));
        assertEquals(PluginSettings.getInstance().getUserAgent(), header(request, "User-Agent"));
    }

    /** Value of a header in a recorded request head, or null when absent. */
    private static String header(List<String> request, String name) {
        String prefix = name.toLowerCase(Locale.ROOT) + ":";
        for (String line : request.subList(1, request.size())) {
            if (line.toLowerCase(Locale.ROOT).startsWith(prefix)) {
                return line.substring(prefix.length()).trim();
            }
        }
        return null;
    }

    /**
     * Forward proxy on the loopback interface. It records the head of every request and answers 403
     * to it, like a proxy whose allowlist does not cover the host. When {@code credentials} ({@code
     * user:password}) is set, a request without those Basic credentials gets a 407 challenge instead.
     */
    private static final class RecordingProxy implements AutoCloseable {
        private final ServerSocket server;
        private final Thread acceptor;
        private final String authorization;
        private final List<List<String>> requests = new CopyOnWriteArrayList<>();

        RecordingProxy(String credentials) throws IOException {
            this.authorization = credentials == null ? null : basic(credentials);
            this.server = new ServerSocket(0, 10, InetAddress.getLoopbackAddress());
            this.acceptor = new Thread(this::serve);
            this.acceptor.start();
        }

        void setJvmProperties() {
            setJvmProperty("https.proxyHost", "127.0.0.1");
            setJvmProperty("https.proxyPort", String.valueOf(this.server.getLocalPort()));
        }

        List<List<String>> requests() {
            return this.requests;
        }

        private void serve() {
            while (!this.server.isClosed()) {
                try (Socket socket = this.server.accept()) {
                    socket.setSoTimeout(5_000);
                    BufferedReader reader =
                            new BufferedReader(
                                    new InputStreamReader(socket.getInputStream(), StandardCharsets.ISO_8859_1));
                    List<String> head = new ArrayList<>();
                    for (String line = reader.readLine();
                            line != null && !line.isEmpty();
                            line = reader.readLine()) {
                        head.add(line);
                    }
                    if (head.isEmpty()) {
                        continue;
                    }
                    this.requests.add(head);
                    String response =
                            this.authorization != null
                                            && !this.authorization.equals(header(head, "Proxy-Authorization"))
                                    ? "HTTP/1.1 407 Proxy Authentication Required\r\n"
                                            + "Proxy-Authenticate: Basic realm=\"proxy\"\r\n"
                                    : "HTTP/1.1 403 Forbidden\r\n";
                    OutputStream out = socket.getOutputStream();
                    out.write(
                            (response + "Content-Length: 0\r\nConnection: close\r\n\r\n")
                                    .getBytes(StandardCharsets.ISO_8859_1));
                    out.flush();
                } catch (IOException e) {
                    // Closed by close(), or a client that went away: keep serving until closed.
                }
            }
        }

        @Override
        public void close() throws Exception {
            this.server.close();
            this.acceptor.join();
        }
    }
}
