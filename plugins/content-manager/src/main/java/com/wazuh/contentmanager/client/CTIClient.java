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
import java.util.concurrent.*;

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

    private static CTIClient INSTANCE;

    private static final int MAX_ATTEMPTS = 3;
    private static final int SLEEP_TIME = 1000;

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

    /** Enum representing the query parameters used in CTI API requests. */
    public enum Functions {
        GET_CHANGES("getChanges"),
        GET_CATALOG("getCatalog");

        private final String value;

        Functions(String value) {
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
        super(URI.create(PluginSettings.getInstance().getCtiBaseUrl()));
    }

    /**
     * Retrieves the singleton instance of {@code CTIClient}.
     *
     * @return The singleton instance of {@code CTIClient}.
     */
    public static synchronized CTIClient getInstance() {
        if (INSTANCE == null) {
            INSTANCE = new CTIClient();
        }
        return INSTANCE;
    }

    /**
     * Fetches content changes from the CTI API using the provided query parameters.
     *
     * @param fromOffset The starting offset (inclusive) for fetching changes.
     * @param toOffset The ending offset (exclusive) for fetching changes.
     * @param withEmpties A flag indicating whether to include empty values (Optional).
     * @return {@link ContextChanges} instance with the current changes.
     */
    public ContextChanges getChanges(String fromOffset, String toOffset, String withEmpties)
            throws HttpException, IllegalArgumentException {
        XContent xContent = XContentType.JSON.xContent();

        Map<String, String> params = contextQueryParameters(fromOffset, toOffset, withEmpties);

        CompletableFuture<SimpleHttpResponse> futureResponse = new CompletableFuture<>();

        fetchWithRetry(
                Functions.GET_CHANGES,
                Method.GET,
                CONSUMER_CHANGES_ENDPOINT,
                null,
                params,
                null,
                MAX_ATTEMPTS);

        SimpleHttpResponse response =
                sendRequest(Method.GET, CONSUMER_CHANGES_ENDPOINT, null, params, (Header) null);
        if (response == null) {
            log.error("No response from CTI API Changes endpoint");
            return null;
        }
        if (response.getCode() != HttpStatus.SC_OK) {
            log.error("CTI API Changes endpoint returned an error: {}", response.getBody());
        }
        log.debug("CTI API Changes endpoint replied with status: [{}]", response.getCode());
        try {
            return ContextChanges.parse(
                    xContent.createParser(
                            NamedXContentRegistry.EMPTY,
                            DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                            response.getBodyBytes()));
        } catch (IOException | IllegalArgumentException e) {
            log.error("Failed to fetch changes information", e);
        }
        return null;
    }

    /**
     * Fetches the entire CTI catalog from the API.
     *
     * @return A {@link ConsumerInfo} object containing the catalog information.
     */
    public ConsumerInfo getCatalog() {
        XContent xContent = XContentType.JSON.xContent();

        CompletableFuture<SimpleHttpResponse> futureResponse = new CompletableFuture<>();
        fetchWithRetry(
                Functions.GET_CATALOG, Method.GET, CONSUMER_INFO_ENDPOINT, null, null, null, MAX_ATTEMPTS);

        SimpleHttpResponse response;

        try {
            response = futureResponse.get();
            if (response == null) {
                log.error("No response from CTI API");
                return null;
            }
            log.debug("CTI API replied with status: [{}]", response.getCode());

            return ConsumerInfo.parse(
                    xContent.createParser(
                            NamedXContentRegistry.EMPTY,
                            DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                            response.getBodyBytes()));
        } catch (IOException | InterruptedException | ExecutionException | IllegalArgumentException e) {
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
            String fromOffset, String toOffset, String withEmpties) throws IllegalArgumentException {
        Map<String, String> params = new HashMap<>();
        params.put(QueryParameters.FROM_OFFSET.getValue(), fromOffset);
        params.put(QueryParameters.TO_OFFSET.getValue(), toOffset);
        if (withEmpties != null && !withEmpties.isEmpty()) {
            params.put(QueryParameters.WITH_EMPTIES.getValue(), withEmpties);
        }
        return params;
    }

    /**
     * Send a request to the CTI API and handles the HTTP response based on the provided status code.
     *
     * @param function The function to be executed.
     * @param method The HTTP method to use for the request.
     * @param endpoint The endpoint to append to the base API URI.
     * @param body The request body (optional, applicable for POST/PUT).
     * @param params The query parameters (optional).
     * @param header The headers to include in the request (optional).
     * @param attemptsLeft The number of remaining attempts.
     * @throws IOException If an error occurs during response processing.
     */
    private SimpleHttpResponse fetchWithRetry(
            Functions function,
            Method method,
            String endpoint,
            String body,
            Map<String, String> params,
            Header header,
            int attemptsLeft) {

        SimpleHttpResponse response = sendRequest(method, endpoint, body, params, header);

        if (response == null) {
            return null;
        }

        int statusCode = response.getCode();
        Header retryAfter = null;
        log.info(
                "Before switch. Response CODE {} - BODY {}",
                response.getCode(),
                response.getBody()); // BORRAR

        switch (statusCode) {
            case 200:
                log.info("Operation succeeded: Status code 200");
                return response;

            case 400:
                log.error("Operation failed: Status code 400 - Error: {}", response.getBodyText());
                return response;

            case 422:
                log.error("Unprocessable Entity: Status code 422 - Error: {}", response.getBodyText());
                return response;

            case 429:
                // If there are more attempts left, wait and retry
                if (attemptsLeft > 0) {
                    log.warn("Too many requests: Status code 429 - Error: {}", response.getBodyText());
                    try {
                        retryAfter = response.getHeader("Retry-After");
                    } catch (ProtocolException e) {
                        log.warn("Too many requests and no Retry-After Header.");
                    }
                } else {
                    log.error("Too many requests: Status code 429 - Error: {}", response.getBodyText());
                    return response;
                }
                break;

            case 500:
                // If there are more attempts left, wait and retry
                if (attemptsLeft > 0) {
                    log.warn("Server Error: Status code 500 - Error: {}", response.getBodyText());
                } else {
                    log.error("Server Error: Status code 500 - Error: {}", response.getBodyText());
                    return response;
                }
                break;

            default:
                log.error("Unexpected status code: {}", statusCode);
                return response;
        }

        Integer timeout = (MAX_ATTEMPTS - attemptsLeft + 1) * SLEEP_TIME;

        // If the Retry-After header is present, use it as the timeout
        if (retryAfter != null) {
            timeout = Integer.parseInt(retryAfter.getValue());
        }
        log.info("Waiting {} ms before retrying", timeout); // BORRAR
        ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
        Future<SimpleHttpResponse> future;
        switch (function) {
            case GET_CHANGES:
                future =
                        scheduler.schedule(
                                (Callable<SimpleHttpResponse>)
                                        () ->
                                                fetchWithRetry(
                                                        Functions.GET_CHANGES,
                                                        Method.GET,
                                                        CONSUMER_CHANGES_ENDPOINT,
                                                        null,
                                                        params,
                                                        null,
                                                        attemptsLeft),
                                timeout,
                                TimeUnit.MILLISECONDS);

                try {
                    return future.get();
                } catch (InterruptedException | ExecutionException e) {
                    // Maneja la excepción
                }

            case GET_CATALOG:
                future =
                        scheduler.schedule(
                                () ->
                                        fetchWithRetry(
                                                Functions.GET_CATALOG,
                                                Method.GET,
                                                CONSUMER_INFO_ENDPOINT,
                                                null,
                                                null,
                                                null,
                                                attemptsLeft),
                                timeout,
                                TimeUnit.MILLISECONDS);
                scheduler.shutdown();

                try {
                    return future.get();
                } catch (InterruptedException | ExecutionException e) {
                    // Maneja la excepción
                }
        }

        return response;
    }

    /***
     * Downloads the CTI snapshot.
     *
     * @param snapshotURI URI to the file to download.
     * @param env environment. Required to resolve files' paths.
     */
    public void download(String snapshotURI, Environment env) {
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
                log.error("Failed to write snapshot {}", e.getMessage());
            }
            log.info("Snapshot downloaded to {}", path);
        } catch (URISyntaxException e) {
            log.error("Failed to download snapshot. Invalid URL provided: {}", e.getMessage());
        } catch (ExecutionException e) {
            log.error("Snapshot download failed: {}", e.getMessage());
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt(); // Restore the interrupted status
            log.error("Snapshot download was interrupted: {}", e.getMessage());
        }
    }
}
