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
package com.wazuh.contentmanager.cti.catalog.client;

import org.apache.hc.client5.http.async.methods.SimpleHttpRequest;
import org.apache.hc.client5.http.async.methods.SimpleRequestBuilder;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;

import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.settings.PluginSettingsTests;

/** Tests {@link ApiClient#executeOnce} against a real socket that never answers. */
public class ApiClientTimeoutTests extends OpenSearchTestCase {

    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettingsTests.clearInstance();
        PluginSettings.getInstance(Settings.EMPTY);
    }

    @Override
    public void tearDown() throws Exception {
        PluginSettingsTests.clearInstance();
        super.tearDown();
    }

    /**
     * A timed-out exchange is cancelled, closing its connection. Without the cancel the connection
     * stays leased until the socket timeout, and a long-lived client runs out of pooled connections.
     */
    public void testTimedOutExchangeReleasesConnection() throws Exception {
        try (ServerSocket server = new ServerSocket(0, 1, InetAddress.getLoopbackAddress());
                ApiClient client = new ApiClient()) {
            SimpleHttpRequest request =
                    SimpleRequestBuilder.get(
                                    "http://"
                                            + server.getInetAddress().getHostAddress()
                                            + ":"
                                            + server.getLocalPort())
                            .build();

            // The kernel completes the handshake from the backlog; the request is never answered.
            expectThrows(TimeoutException.class, () -> client.executeOnce(request, 1));

            try (Socket accepted = server.accept()) {
                // Shorter than the client's socket timeout (10 s): only a cancel closes it in time.
                accepted.setSoTimeout(5_000);
                InputStream in = accepted.getInputStream();
                byte[] buffer = new byte[1024];
                try {
                    while (in.read(buffer) != -1) {
                        // Drain the request bytes until the client closes the connection.
                    }
                } catch (SocketException e) {
                    // The cancel aborts the connection: a reset is as good as an orderly close.
                } catch (SocketTimeoutException e) {
                    fail("The timed-out exchange kept its connection open");
                }
            }
        }
    }
}
