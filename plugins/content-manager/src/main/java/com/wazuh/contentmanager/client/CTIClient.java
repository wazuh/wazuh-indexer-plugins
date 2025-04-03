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

    private static final String API_BASE_URL = PluginSettings.getInstance().getCtiBaseUrl();
    private static final String CONSUMER_INFO_ENDPOINT =
            "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";
    private static final String CONSUMER_CHANGES_ENDPOINT = "/changes";

    private static final int MAX_OFFSETS = 1000;
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
    public SimpleHttpResponse getChanges(String fromOffset, String toOffset, String withEmpties)
            throws HttpException, IllegalArgumentException {
        Map<String, String> params = contextQueryParameters(fromOffset, toOffset, withEmpties);
        CompletableFuture<SimpleHttpResponse> futureResponse = new CompletableFuture<>();
        fetchWithRetry(
                Functions.GET_CHANGES,
                Method.GET,
                CONSUMER_CHANGES_ENDPOINT,
                null,
                params,
                null,
                MAX_ATTEMPTS,
                futureResponse);

        try {
            return futureResponse.get();
        } catch (InterruptedException | ExecutionException e) {
            throw new HttpException("Failed to fetch changes: " + e.getMessage(), e);
        }
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
            String fromOffset, String toOffset, String withEmpties) throws IllegalArgumentException {
        Map<String, String> params = new HashMap<>();
        if (fromOffset == null) {
            throw new IllegalArgumentException("fromOffset cannot be null");
        }
        if (toOffset == null) {
            throw new IllegalArgumentException("toOffset cannot be null");
        }
        Long longFromOffset = Long.parseLong(fromOffset);
        Long longToOffset = Long.parseLong(toOffset);
        long difference = longToOffset - longFromOffset;
        if (longToOffset < longFromOffset || difference > MAX_OFFSETS) {
            throw new IllegalArgumentException(
                    "toOffset cannot be less than fromOffset or the difference cannot be greater than "
                            + MAX_OFFSETS);
        }

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
     * @param futureResponse The CompletableFuture to complete with the response.
     * @throws IOException If an error occurs during response processing.
     */
    private void fetchWithRetry(
            Functions function,
            Method method,
            String endpoint,
            String body,
            Map<String, String> params,
            Header header,
            int attemptsLeft,
            CompletableFuture<SimpleHttpResponse> futureResponse) {
        SimpleHttpResponse response = sendRequest(method, endpoint, body, params, header);

        int statusCode = response.getCode();
        Boolean retry = false;

        switch (statusCode) {
            case 200:
                log.info("Operation succeeded: Status code 200");
                futureResponse.complete(response);
                break;
            case 400:
                futureResponse.completeExceptionally(
                        new HttpException(
                                "Operation failed: Status code 400 - Error: " + response.getBodyText()));
                break;
            case 429:
                if (attemptsLeft > 0) {
                    log.warn("Too many requests: Status code 429 - Error: {}", response.getBodyText());
                    retry = true;
                } else {
                    futureResponse.completeExceptionally(
                            new HttpException(
                                    "Too many requests: Status code 429 - Error: " + response.getBodyText()));
                }
                break;
            case 422:
                if (attemptsLeft > 0) {
                    log.warn("Unprocessable Entity: Status code 422 - Error: {}", response.getBodyText());
                    retry = true;
                } else {
                    futureResponse.completeExceptionally(
                            new HttpException(
                                    "Server Error: Status code 500 - Error: " + response.getBodyText()));
                }
                break;
            case 500:
                if (attemptsLeft > 0) {
                    log.error("Server Error: Status code 500 - Error: {}", response.getBodyText());
                    retry = true;
                } else {
                    futureResponse.completeExceptionally(
                            new HttpException(
                                    "Server Error: Status code 500 - Error: " + response.getBodyText()));
                }
                break;
            default:
                log.error("Unexpected status code: {}", statusCode);
                futureResponse.completeExceptionally(
                        new HttpException(
                                "Unexpected status code: " + statusCode + " - Error: " + response.getBodyText()));
                break;
        }

        if (retry) {
            ScheduledExecutorService scheduler = Executors.newSingleThreadScheduledExecutor();
            int timeout = (MAX_ATTEMPTS - attemptsLeft + 1) * SLEEP_TIME;
            switch (function) {
                case GET_CHANGES:
                    scheduler.schedule(
                            () ->
                                    fetchWithRetry(
                                            Functions.GET_CHANGES,
                                            Method.GET,
                                            CONSUMER_CHANGES_ENDPOINT,
                                            null,
                                            params,
                                            null,
                                            attemptsLeft,
                                            futureResponse),
                            timeout,
                            TimeUnit.MILLISECONDS);
                    scheduler.shutdown();
                    break;
                case GET_CATALOG:
                    scheduler.schedule(
                            () ->
                                    fetchWithRetry(
                                            Functions.GET_CATALOG,
                                            Method.GET,
                                            CONSUMER_INFO_ENDPOINT,
                                            null,
                                            null,
                                            null,
                                            attemptsLeft,
                                            futureResponse),
                            timeout,
                            TimeUnit.MILLISECONDS);
                    scheduler.shutdown();
                    break;
                default:
                    break;
            }
        }
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
            log.error("Snapshot download was interrupted: {}", e.getMessage());
        }
    }

    /**
     * Handles the HTTP response based on the provided status code.
     *
     * @param response The HTTP response to be handled.
     * @throws IOException If an error occurs during response processing.
     */
    private void handleHttpResponse(SimpleHttpResponse response) throws IOException {
        int statusCode = response.getCode();
    }
}
