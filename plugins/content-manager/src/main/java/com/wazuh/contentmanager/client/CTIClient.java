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

import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.impl.async.CloseableHttpAsyncClient;
import org.apache.hc.client5.http.impl.async.HttpAsyncClients;
import org.apache.hc.client5.http.impl.nio.PoolingAsyncClientConnectionManagerBuilder;
import org.apache.hc.client5.http.ssl.ClientTlsStrategyBuilder;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.Method;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContent;

import java.io.IOException;
import java.net.URI;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.apache.hc.core5.ssl.SSLContextBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import javax.net.ssl.SSLContext;

/**
 * CTIClient is a singleton class responsible for interacting with the Cyber Threat Intelligence
 * (CTI) API. It extends {@link HttpClient} to manage HTTP requests.
 *
 * <p>This client provides methods to fetch CTI catalog data and retrieve content changes based on
 * query parameters.
 */
public class CTIClient extends HttpClient {

    private static final Logger log = LogManager.getLogger(CTIClient.class);

    private static final String API_BASE_URL = PluginSettings.getInstance().getCtiBaseUrl();
    private static final String CONSUMER_INFO_ENDPOINT =
            "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";
    private static final String CONSUMER_CHANGES_ENDPOINT = "/changes";

    /** Enum representing the query parameters used in CTI API requests. */
    public enum QueryParameters {
        /** The starting offset parameter TO_OFFSET - FROM_OFFSET must be >1001 */
        FROM_OFFSET("from_offset"),
        /** The destination offset parameter */
        TO_OFFSET("to_offset"),
        /** Include empties */
        WITH_EMPTIES("with_empties");

        private final String value;

        QueryParameters(String value) {
            this.value = value;
        }

        /**
         * Returns the string representation of the query parameter.
         *
         * @return The query parameter key as a string.
         */
        public String getValue() {
            return value;
        }
    }

    /**
     * Private constructor to enforce singleton pattern. Initializes the client with the CTI API base
     * URL.
     */
    private CTIClient() {
        super(URI.create(API_BASE_URL));
    }

    /** Singleton holder pattern ensures lazy initialization in a thread-safe manner. */
    private static class CTIClientHolder {
        private static final CTIClient INSTANCE = new CTIClient();
    }

    /**
     * Retrieves the singleton instance of {@code CTIClient}.
     *
     * @return The singleton instance of {@code CTIClient}.
     */
    public static CTIClient getInstance() {
        return CTIClientHolder.INSTANCE;
    }

    /**
     * Fetches content changes from the CTI API using the provided query parameters.
     *
     * @param fromOffset The starting offset (inclusive) for fetching changes.
     * @param toOffset The ending offset (exclusive) for fetching changes.
     * @param withEmpties A flag indicating whether to include empty values (Optional).
     * @return A {@link SimpleHttpResponse} containing the API response.
     */
    public SimpleHttpResponse getChanges(String fromOffset, String toOffset, String withEmpties) {
        Map<String, String> params = contextQueryParameters(fromOffset, toOffset, withEmpties);
        return sendRequest(Method.GET, CONSUMER_CHANGES_ENDPOINT, null, params, (Header) null);
    }

    /**
     * Fetches the entire CTI catalog from the API.
     *
     * @return A {@link SimpleHttpResponse} containing the API response with the catalog data.
     */
    public ConsumerInfo getCatalog() {
        XContent xContent = XContentType.JSON.xContent();
        SimpleHttpResponse response =
                sendRequest(Method.GET, CONSUMER_INFO_ENDPOINT, null, null, (Header) null);
        if (response == null) {
            log.error("No response from CTI API");
            return null;
        }
        log.debug("CTI API replied with status: [{}]", response.getCode());
        try {
            return ConsumerInfo.parse(
                    xContent.createParser(
                            NamedXContentRegistry.EMPTY,
                            DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                            response.getBodyBytes()));
        } catch (IOException | IllegalArgumentException e) {
            log.error("Unable to fetch catalog information: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Builds a map of query parameters for the API request to fetch context changes.
     *
     * @param fromOffset The starting offset (inclusive).
     * @param toOffset The ending offset (exclusive).
     * @param withEmpties A flag indicating whether to include empty values. If null or empty, it will
     *     be ignored.
     * @return A map containing the query parameters.
     */
    public static Map<String, String> contextQueryParameters(
            String fromOffset, String toOffset, String withEmpties) {
        Map<String, String> params = new HashMap<>();
        params.put(QueryParameters.FROM_OFFSET.getValue(), fromOffset);
        params.put(QueryParameters.TO_OFFSET.getValue(), toOffset);
        if (withEmpties != null && !withEmpties.isEmpty()) {
            params.put(QueryParameters.WITH_EMPTIES.getValue(), withEmpties);
        }
        return params;
    }

    /**
     * Downloads the CTI snapshot into the /build/testclusters/integTest-0/distro/2.19.1-INTEG_TEST route.
     *
     * @param snapshotURI It will have the URI used for the download, at the moment that URI is hardcoded.
     */
    public void downloadSnapshot(String snapshotURI) {
        try {
            // This Uri will be changed to use the param snapshotURI once issue 310 is merged
            URI uri = new URI(snapshotURI);
            String fileName =  uri.getPath().substring(uri.getPath().lastIndexOf('/') + 1);

            // Initialize the client this can be changed once 310 is merged to use HTTPClient client instead of creating a new one
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
