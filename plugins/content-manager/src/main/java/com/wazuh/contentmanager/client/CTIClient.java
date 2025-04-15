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
import java.time.Duration;
import java.time.ZonedDateTime;
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
public final class CTIClient extends HttpClient {

    private static final Logger log = LogManager.getLogger(CTIClient.class);

    private static final String CONSUMER_INFO_ENDPOINT =
            "/catalog/contexts/" + PluginSettings.CONTEXT_ID + "/consumers/" + PluginSettings.CONSUMER_ID;
    private static final String CONSUMER_CHANGES_ENDPOINT = CONSUMER_INFO_ENDPOINT + "/changes";

    private static CTIClient INSTANCE;

    private static final int MAX_ATTEMPTS = 3;
    private static final int SLEEP_TIME = 60;

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
            throws IllegalArgumentException {
        XContent xContent = XContentType.JSON.xContent();

        Map<String, String> params = contextQueryParameters(fromOffset, toOffset, withEmpties);

        SimpleHttpResponse response =
                fetchWithRetry(Method.GET, CONSUMER_CHANGES_ENDPOINT, null, params, null);

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

        try {
            SimpleHttpResponse response =
                    fetchWithRetry(Method.GET, CONSUMER_INFO_ENDPOINT, null, null, null);

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
     * @param method The HTTP method to use for the request.
     * @param endpoint The endpoint to append to the base API URI.
     * @param body The request body (optional, applicable for POST/PUT).
     * @param params The query parameters (optional).
     * @param header The headers to include in the request (optional).
     * @throws IOException If an error occurs during response processing.
     */
    private SimpleHttpResponse fetchWithRetry(
            Method method, String endpoint, String body, Map<String, String> params, Header header) {

        ZonedDateTime cooldown = null;
        int attemptsLeft = CTIClient.MAX_ATTEMPTS;

        while (attemptsLeft > 0) {
            // Check if in cooldown
            if (cooldown != null && ZonedDateTime.now().isBefore(cooldown)) {
                long waitTime = Duration.between(ZonedDateTime.now(), cooldown).getSeconds();
                log.info("In cooldown, waiting {} seconds", waitTime);
                try {
                    Thread.sleep(waitTime * 1000); // Wait before retrying
                } catch (InterruptedException e) {
                    log.error("Interrupted while waiting for cooldown", e);
                    Thread.currentThread().interrupt(); // Reset interrupt status
                }
            }

            log.info("Making request to CTI API");
            SimpleHttpResponse response = sendRequest(method, endpoint, body, params, header);

            if (response == null) {
                return null; // Handle null
            }

            int statusCode = response.getCode();
            log.info("Response code: {}", statusCode);

            // Calculate timeout
            int timeout = (CTIClient.MAX_ATTEMPTS - attemptsLeft + 1) * CTIClient.SLEEP_TIME;

            switch (statusCode) {
                case 200:
                    log.info("Operation succeeded: status code 200");
                    return response;

                case 400:
                    log.error("Operation failed: status code 400 - Error: {}", response.getBodyText());
                    return response;

                case 422:
                    log.error("Unprocessable Entity: status code 422 - Error: {}", response.getBodyText());
                    return response;

                case 429: // Handling Too Many Requests
                    log.warn("Max requests limit reached: status code 429");
                    try {
                        String retryAfterValue = response.getHeader("Retry-After").getValue();
                        if (retryAfterValue != null) {
                            timeout = Integer.parseInt(retryAfterValue);
                        }
                        cooldown = ZonedDateTime.now().plusSeconds(timeout); // Set cooldown
                        log.info("Cooldown until {}", cooldown);
                    } catch (ProtocolException | NullPointerException e) {
                        log.warn("Retry-After header not present or invalid format: {}", e.getMessage());
                        cooldown = ZonedDateTime.now().plusSeconds(timeout); // Default cooldown
                    }
                    break;

                case 500: // Handling Server Error
                    log.warn("Server Error: status code 500 - Error: {}", response.getBodyText());
                    cooldown = ZonedDateTime.now().plusSeconds(60); // Set cooldown for server errors
                    break;

                default:
                    log.error("Unexpected status code: {}", statusCode);
                    return response;
            }

            attemptsLeft--; // Decrease remaining attempts
        }

        log.error("All attempts exhausted for the request to CTI API.");
        return null; // Return null if all attempts fail
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
