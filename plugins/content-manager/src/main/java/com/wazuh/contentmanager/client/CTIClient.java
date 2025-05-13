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

import org.apache.hc.client5.http.HttpHostConnectException;
import org.apache.hc.client5.http.async.methods.*;
import org.apache.hc.client5.http.classic.methods.HttpGet;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.client5.http.impl.classic.HttpClients;
import org.apache.hc.core5.http.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.env.Environment;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.ZonedDateTime;
import java.util.*;
import java.util.concurrent.*;

import com.wazuh.contentmanager.model.cti.ConsumerInfo;
import com.wazuh.contentmanager.model.cti.ContentChanges;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.XContentUtils;
import reactor.util.annotation.NonNull;

/**
 * CTIClient is a singleton class responsible for interacting with the Cyber Threat Intelligence
 * (CTI) API. It extends {@link HttpClient} to manage HTTP requests.
 *
 * <p>This client provides methods to fetch CTI catalog data and retrieve content changes based on
 * query parameters.
 */
public class CTIClient extends HttpClient {
    private static final Logger log = LogManager.getLogger(CTIClient.class);

    static final String CONSUMER_INFO_ENDPOINT =
            "/catalog/contexts/" + PluginSettings.CONTEXT_ID + "/consumers/" + PluginSettings.CONSUMER_ID;
    private static final String CONSUMER_CHANGES_ENDPOINT = CONSUMER_INFO_ENDPOINT + "/changes";
    static final int MAX_ATTEMPTS = 3;
    private static final int SLEEP_TIME = 60;

    private static CTIClient INSTANCE;

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
            return this.value;
        }
    }

    /** Public constructor method */
    public CTIClient() {
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
     * This constructor is only used on tests.
     *
     * @param CTIBaseURL base URL of the CTI API (mocked).
     */
    CTIClient(String CTIBaseURL) {
        super(URI.create(CTIBaseURL));
    }

    /**
     * Fetches content changes from the CTI API using the provided query parameters.
     *
     * @param fromOffset The starting offset (inclusive) for fetching changes.
     * @param toOffset The ending offset (exclusive) for fetching changes.
     * @param withEmpties A flag indicating whether to include empty values (Optional).
     * @return {@link ContentChanges} instance with the current changes.
     */
    public ContentChanges getChanges(long fromOffset, long toOffset, boolean withEmpties) {
        Map<String, String> params =
                CTIClient.contextQueryParameters(fromOffset, toOffset, withEmpties);
        SimpleHttpResponse response =
                this.sendRequest(
                        Method.GET, CONSUMER_CHANGES_ENDPOINT, null, params, null, CTIClient.MAX_ATTEMPTS);

        // Fail fast
        if (response == null) {
            log.error("No response from CTI API Changes endpoint");
            return new ContentChanges();
        }
        if (!Arrays.asList(HttpStatus.SC_OK, HttpStatus.SC_SUCCESS).contains(response.getCode())) {
            log.error("CTI API Changes endpoint returned an error: {}", response.getBody());
            return new ContentChanges();
        }

        log.debug("CTI API Changes endpoint replied with status: [{}]", response.getCode());
        try {
            return ContentChanges.parse(XContentUtils.createJSONParser(response.getBodyBytes()));
        } catch (IOException | IllegalArgumentException e) {
            log.error("Failed to fetch changes information due to: {}", e.getMessage());
            return new ContentChanges();
        }
    }

    /**
     * Fetches the entire CTI catalog from the API.
     *
     * @return A {@link ConsumerInfo} object containing the catalog information.
     * @throws HttpHostConnectException server unreachable.
     * @throws IOException error parsing response.
     */
    public ConsumerInfo getConsumerInfo() throws HttpHostConnectException, IOException {
        // spotless:off
        SimpleHttpResponse response = this.sendRequest(
            Method.GET,
            CONSUMER_INFO_ENDPOINT,
            null,
            null,
            null,
            CTIClient.MAX_ATTEMPTS
        );
        // spotless:on
        if (response == null) {
            throw new HttpHostConnectException("No reply to " + CONSUMER_INFO_ENDPOINT);
        }
        log.debug("CTI API replied with status: [{}]", response.getCode());
        return ConsumerInfo.parse(XContentUtils.createJSONParser(response.getBodyBytes()));
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
            long fromOffset, long toOffset, boolean withEmpties) {
        Map<String, String> params = new HashMap<>();
        params.put(QueryParameters.FROM_OFFSET.getValue(), String.valueOf(fromOffset));
        params.put(QueryParameters.TO_OFFSET.getValue(), String.valueOf(toOffset));
        params.put(QueryParameters.WITH_EMPTIES.getValue(), String.valueOf(withEmpties));
        return params;
    }

    /**
     * Send a request to the CTI API and handles the HTTP response based on the provided status code.
     *
     * <p>Implements a retry strategy based on {@code attemptsLeft}
     *
     * @param method The HTTP method to use for the request.
     * @param endpoint The endpoint to append to the base API URI.
     * @param body The request body (optional, applicable for POST/PUT).
     * @param params The query parameters (optional).
     * @param header The headers to include in the request (optional).
     * @param attemptsLeft number of retries left.
     * @return SimpleHttpResponse or null.
     */
    protected SimpleHttpResponse sendRequest(
            @NonNull Method method,
            @NonNull String endpoint,
            String body,
            Map<String, String> params,
            Header header,
            int attemptsLeft) {
        // TODO used to debug the failing test "testGetChanges_SuccessfulRequest".
        // log.error("sendRequest {} {} {} {} {} {}", method, endpoint, body, params, header,
        // attemptsLeft);
        ZonedDateTime cooldown = null;
        SimpleHttpResponse response = null;
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

            int currentAttempt = CTIClient.MAX_ATTEMPTS - attemptsLeft + 1;
            log.debug(
                    "Sending {} request to [{}]. Attempt {}/{}.",
                    method,
                    endpoint,
                    currentAttempt,
                    MAX_ATTEMPTS);
            // WARN Changing this to sendRequest makes the test fail.
            response = this.doHttpClientSendRequest(method, endpoint, body, params, header);
            if (response == null) {
                return null; // Handle null
            }

            // Calculate timeout
            int timeout = currentAttempt * CTIClient.SLEEP_TIME;
            int statusCode = response.getCode();
            switch (statusCode) {
                case 200:
                    log.info("Operation succeeded: status code {} - {}", statusCode, response.getBodyText());
                    return response;

                case 400:
                    log.error(
                            "Operation failed: status code {} - Error: {}", statusCode, response.getBodyText());
                    return response;

                case 422:
                    log.error(
                            "Unprocessable Entity: status code {} - Error: {}",
                            statusCode,
                            response.getBodyText());
                    return response;

                case 429: // Handling Too Many Requests
                    log.warn("Max requests limit reached: status code {}", statusCode);
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
                    log.warn("Server Error: status code {} - Error: {}", statusCode, response.getBodyText());
                    cooldown = ZonedDateTime.now().plusSeconds(60); // Set cooldown for server errors
                    break;

                default:
                    log.error("Unexpected status code: {}", statusCode);
                    return response;
            }
            attemptsLeft--; // Decrease remaining attempts
        }

        log.error("All attempts exhausted for the request to CTI API.");
        return response; // Return null if all attempts fail
    }

    /***
     * Downloads the CTI snapshot.
     *
     * @param snapshotURI URI to the file to download.
     * @param env environment. Required to resolve files' paths.
     * @return The downloaded file's name
     */
    public Path download(String snapshotURI, Environment env) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            // Setup
            final URI uri = new URI(snapshotURI);
            final HttpGet request = new HttpGet(uri);
            final String filename = uri.getPath().substring(uri.getPath().lastIndexOf('/') + 1);
            final Path path = env.tmpFile().resolve(filename);

            // Download
            log.info("Starting snapshot download from [{}]", uri);
            try (CloseableHttpResponse response = client.execute(request)) {
                if (response.getEntity() != null) {
                    // Write to disk
                    InputStream input = response.getEntity().getContent();
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
                    }
                }
            }
            log.info("Snapshot downloaded to {}", path);
            return path;
        } catch (URISyntaxException e) {
            log.error("Failed to download snapshot. Invalid URL provided: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Snapshot download failed: {}", e.getMessage());
        }
        return null;
    }

    /**
     * Sends an HTTP request to the specified endpoint using the provided method, body, parameters,
     * and header.
     *
     * <p>This method is intentionally separated from the main logic to facilitate mocking in unit
     * tests.
     *
     * @param method the HTTP method to use (e.g. GET, POST, PUT, etc.)
     * @param endpoint the URL of the endpoint to send the request to
     * @param body the request body, or null if no body is required
     * @param params a map of query parameters to include in the request, or null if no parameters are
     *     required
     * @param header the request header, or null if no header is required
     * @return the response from the server, or null if an error occurs
     */
    protected SimpleHttpResponse doHttpClientSendRequest(
            Method method, String endpoint, String body, Map<String, String> params, Header header) {
        return super.sendRequest(method, endpoint, body, params, header);
    }
}
