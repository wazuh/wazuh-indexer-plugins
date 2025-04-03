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
import org.apache.hc.core5.http.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContent;
import org.opensearch.env.Environment;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;

import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.model.ctiapi.ContextChanges;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * CTIClient is a singleton class responsible for interacting with the Cyber Threat Intelligence
 * (CTI) API. It extends {@link HttpClient} to manage HTTP requests.
 *
 * <p>This client provides methods to fetch CTI catalog data and retrieve content changes based on
 * query parameters.
 */
public class CTIClient extends HttpClient {

    private static final Logger log = LogManager.getLogger(CTIClient.class);

    private static final String CONSUMER_INFO_ENDPOINT =
            "/catalog/contexts/" + PluginSettings.CONTEXT_ID + "/consumers/" + PluginSettings.CONSUMER_ID;
    private static final String CONSUMER_CHANGES_ENDPOINT = CONSUMER_INFO_ENDPOINT + "/changes";

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
     *
     * @throws HttpClientException If an error occurs while creating the HTTP client.
     */
    private CTIClient() throws HttpClientException {
        super(URI.create(PluginSettings.getInstance().getCtiBaseUrl()));
    }

    /** Singleton holder pattern ensures lazy initialization in a thread-safe manner. */
    private static class CTIClientHolder {
        private static final CTIClient INSTANCE;

        static {
            try {
                INSTANCE = new CTIClient();
            } catch (HttpClientException e) {
                throw new RuntimeException(e);
            }
        }
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
     * @return {@link ContextChanges} instance with the current changes.
     * @throws HttpClientException If an error occurs while fetching changes.
     */
    public ContextChanges getChanges(String fromOffset, String toOffset, String withEmpties)
            throws HttpClientException {
        XContent xContent = XContentType.JSON.xContent();
        Map<String, String> params = contextQueryParameters(fromOffset, toOffset, withEmpties);
        SimpleHttpResponse response =
                sendRequest(Method.GET, CONSUMER_CHANGES_ENDPOINT, null, params, (Header) null);
        if (response == null) {
            throw new HttpClientException("No response from CTI API Changes endpoint");
        }
        if (response.getCode() != HttpStatus.SC_OK) {
            throw new HttpClientException(
                    "CTI API Changes endpoint returned an error: " + response.getBody());
        }
        log.debug("CTI API Changes endpoint replied with status: [{}]", response.getCode());
        try {
            return ContextChanges.parse(
                    xContent.createParser(
                            NamedXContentRegistry.EMPTY,
                            DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                            response.getBodyBytes()));
        } catch (IOException | IllegalArgumentException e) {
            throw new HttpClientException("Failed to fetch changes information", e);
        }
    }

    /**
     * Fetches the entire CTI catalog from the API.
     *
     * @return A {@link ConsumerInfo} object containing the catalog information.
     * @throws HttpClientException If an error occurs while fetching the catalog.
     */
    public ConsumerInfo getCatalog() throws HttpClientException {
        XContent xContent = XContentType.JSON.xContent();
        SimpleHttpResponse response =
                sendRequest(Method.GET, CONSUMER_INFO_ENDPOINT, null, null, (Header) null);
        if (response == null) {
            throw new HttpClientException("No response from CTI API");
        }
        if (response.getCode() != HttpStatus.SC_OK) {
            throw new HttpClientException("CTI API returned an error: " + response.getBody());
        }
        log.debug("CTI API replied with status: [{}]", response.getCode());
        try {
            return ConsumerInfo.parse(
                    xContent.createParser(
                            NamedXContentRegistry.EMPTY,
                            DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                            response.getBodyBytes()));
        } catch (IOException | IllegalArgumentException e) {
            throw new HttpClientException("Failed to fetch consumer information", e);
        }
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

    /***
     * Downloads the CTI snapshot.
     *
     * @param snapshotURI URI to the file to download.
     * @param env environment. Required to resolve files' paths.
     */
    public void download(String snapshotURI, Environment env) throws HttpClientException {
        try {
            // Setup
            URI uri = new URI(snapshotURI);
            String filename = uri.getPath().substring(uri.getPath().lastIndexOf('/') + 1);
            Path path = env.resolveRepoFile(filename);

            // Download
            log.info("Starting snapshot download from [{}]", uri);
            SimpleHttpRequest request = SimpleHttpRequest.create(Method.GET, uri);
            SimpleHttpResponse response = httpClient.execute(request, null).get();

            // Write to disk
            InputStream input = new ByteArrayInputStream(response.getBodyBytes());
            try (OutputStream out =
                    new BufferedOutputStream(
                            Files.newOutputStream(
                                    path,
                                    StandardOpenOption.CREATE,
                                    StandardOpenOption.WRITE,
                                    StandardOpenOption.TRUNCATE_EXISTING))) {

                int bytesRead;
                byte[] buffer = new byte[1024];
                while ((bytesRead = input.read(buffer)) != -1) {
                    out.write(buffer, 0, bytesRead);
                }
            } catch (IOException e) {
                throw new HttpClientException("Failed to write snapshot", e);
            }
            log.info("Snapshot downloaded to {}", path);
        } catch (URISyntaxException e) {
            throw new HttpClientException("Invalid URL provided", e);
        } catch (ExecutionException e) {
            throw new HttpClientException("Snapshot download failed", e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore the interrupted status
            throw new HttpClientException("Snapshot download was interrupted", e);
        }
    }
}
