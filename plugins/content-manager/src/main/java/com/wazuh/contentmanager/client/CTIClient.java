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
package com.wazuh.contentmanager.client;

import com.wazuh.contentmanager.util.Privileged;
import com.wazuh.contentmanager.util.http.HttpResponseCallback;
import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Method;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyManagementException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.settings.PluginSettings;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;

/**
 * CTIClient is a singleton class responsible for interacting with the CTI (Cyber Threat
 * Intelligence) API. It extends HttpClient to handle HTTP requests.
 */
public class CTIClient extends HttpClient {
    private static CTIClient instance;

    private static final String apiUrl =
            PluginSettings.getInstance().getCtiBaseUrl()
                    + "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";
    private static final String CONTENT_CHANGES_ENDPOINT = "/changes";

    private static final Logger log = LogManager.getLogger(CTIClient.class);
    /**
     * Private constructor to enforce singleton pattern. Initializes the HTTP client with the CTI API
     * base URL.
     */
    protected CTIClient() {
        super(URI.create(apiUrl));
    }

    /**
     * Retrieves the singleton instance of CTIClient. Ensures thread-safe lazy initialization.
     *
     * @return The singleton instance of CTIClient.
     */
    public static CTIClient getInstance() {
        if (instance == null) {
            synchronized (CTIClient.class) {
                if (instance == null) {
                    instance = new CTIClient();
                }
            }
        }
        return instance;
    }

    /**
     * Fetches content changes from the CTI API.
     *
     * @param queryParameters A map containing query parameters to filter the request.
     * @return A SimpleHttpResponse containing the response from the API.
     */
    public SimpleHttpResponse getChanges(Map<String, String> queryParameters) {
        return sendRequest(Method.GET, CONTENT_CHANGES_ENDPOINT, null, queryParameters, (Header) null);
    }

    /**
     * Fetches the entire CTI catalog from the API.
     *
     * @return A SimpleHttpResponse containing the response from the API.
     */
    public SimpleHttpResponse getCatalog() {
        return sendRequest(Method.GET, null, null, null, (Header) null);
    }

    /**
     * Downloads the CTI snapshot into the /build/testclusters/integTest-0/distro/2.19.1-INTEG_TEST route.
     *
     * @param snapshotURI It will have the URI used for the download, at the moment that URI is hardcoded.
     */
    public void downloadSnapshot(String snapshotURI) {
        try {
            // This Uri will be changed to use the param snapshotURI once issue 310 is merged
            URI uri = new URI("https://cti.wazuh.com/store/contexts/vd_1.0.0/consumers/vd_4.8.0/1432540_1741603172.zip");
            String fileName =  uri.getPath().substring(uri.getPath().lastIndexOf('/') + 1);

            // Initialize the client
            CloseableHttpAsyncClient snapshotClient;
            Object LOCK = new Object();

            synchronized (LOCK) {
                try {
                    SSLContext sslContext = SSLContextBuilder.create()
                        .loadTrustMaterial(null, (chains, authType) -> true)
                        .build();

                    snapshotClient = HttpAsyncClients.custom()
                        .setConnectionManager(
                            PoolingAsyncClientConnectionManagerBuilder.create()
                                .setTlsStrategy(
                                    ClientTlsStrategyBuilder.create().setSslContext(sslContext).build())
                                .build())
                        .build();
                    snapshotClient.start();
                } catch (NoSuchAlgorithmException | KeyStoreException | KeyManagementException e) {
                    log.error("Error initializing HTTP snapshot download client: {}", e.getMessage());
                    throw new RuntimeException("Failed to initialize snapshot download client", e);
                }
            }

            // Create and send the request
            log.info("Sending GET request to [{}]", uri);

            SimpleRequestBuilder builder = SimpleRequestBuilder.create(Method.GET);
            SimpleHttpRequest request = builder.setHttpHost(HttpHost.create("https://cti.wazuh.com"))
                .setPath(uri.getPath())
                .build();

            SimpleHttpResponse response = snapshotClient.execute(request, null).get();

            // Streamed download
            try (InputStream in = new ByteArrayInputStream(response.getBodyBytes());
                 FileOutputStream out = new FileOutputStream(fileName)) {

                byte[] buffer = new byte[1024];
                int bytesRead;

                while ((bytesRead = in.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }

                log.info("Successfully downloaded to: {}", fileName);
            } catch (IOException e) {
                log.error("Error downloading the file: {}", e.getMessage());
            }
        } catch (Exception e) {
            log.error("Error during request: {}", e.getMessage());
        }
    }

}
