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
package com.wazuh.contentmanager.engine.client;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.SuppressForbidden;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.SocketTimeoutException;
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.AccessDeniedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessController;
import java.security.PrivilegedActionException;
import java.security.PrivilegedExceptionAction;

import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Client for communicating with the Wazuh Engine through a Unix domain socket.
 *
 * <p>This client handles JSON-based HTTP communication over a Unix socket. Each request opens a new
 * connection that is closed after receiving the response.
 */
public class EngineSocketClient {
    private static final Logger logger = LogManager.getLogger(EngineSocketClient.class);
    private static final String DEFAULT_SOCKET_PATH =
            "/usr/share/wazuh-indexer/engine/sockets/engine-api.sock";
    private static final int BUFFER_SIZE = 8192;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private final String socketPath;

    /** Creates a EngineSocketClient with the default socket path. */
    public EngineSocketClient() {
        this(DEFAULT_SOCKET_PATH);
    }

    /**
     * Creates a EngineSocketClient with a custom socket path.
     *
     * @param socketPath the path to the Unix domain socket
     */
    public EngineSocketClient(String socketPath) {
        this.socketPath = socketPath;
    }

    /**
     * Sends a request to the Engine API through the Unix socket.
     *
     * @param endpoint the API endpoint (e.g., "/router/table/get")
     * @param method the HTTP method (e.g., "POST", "GET")
     * @param payload the JSON payload to send
     * @return a RestResponse containing the status and message from the Engine
     */
    @SuppressForbidden(reason = "Unix domain socket connection required for Engine communication")
    public RestResponse sendRequest(String endpoint, String method, JsonNode payload) {
        Path socketFile = Path.of(this.socketPath);

        if (!Files.exists(socketFile)) {
            logger.error(Constants.E_LOG_ENGINE_SOCKET_UNAVAILABLE);
            logger.debug(Constants.D_LOG_ENGINE_SOCKET_NOT_FOUND, this.socketPath);
            return new RestResponse("Socket file not found at " + this.socketPath, 500);
        }

        try {
            return AccessController.doPrivileged(
                    (PrivilegedExceptionAction<RestResponse>)
                            () -> executeSocketRequest(socketFile, endpoint, method, payload));
        } catch (PrivilegedActionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof SocketTimeoutException) {
                logger.error(Constants.E_LOG_ENGINE_TIMEOUT, cause.getMessage());
                return new RestResponse("Timed out communicating with the Engine.", 500);
            } else if (cause instanceof AccessDeniedException) {
                logger.error(Constants.E_LOG_ENGINE_PERMISSION_DENIED);
                return new RestResponse("Permission denied accessing the Engine.", 500);
            } else if (cause instanceof IOException) {
                logger.error(Constants.E_LOG_ENGINE_COMMUNICATION_FAILED, cause.getMessage(), cause);
                return new RestResponse("Failed to communicate with the Engine.", 500);
            } else {
                logger.error(Constants.E_LOG_ENGINE_UNEXPECTED_ERROR, cause.getMessage(), cause);
                return new RestResponse("Unexpected error communicating with the Engine.", 500);
            }
        } catch (Exception e) {
            logger.error(Constants.E_LOG_ENGINE_UNEXPECTED_ERROR, e.getMessage(), e);
            return new RestResponse("Unexpected error communicating with the Engine.", 500);
        }
    }

    /**
     * Executes the actual socket communication within a privileged context. This is needed because
     * transport actions may run on threads whose call stack includes other plugins that lack
     * socket permissions.
     */
    @SuppressForbidden(reason = "Unix domain socket access requires privileged execution")
    private RestResponse executeSocketRequest(
            Path socketFile, String endpoint, String method, JsonNode payload) throws IOException {
        UnixDomainSocketAddress address = UnixDomainSocketAddress.of(socketFile);

        try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
            channel.connect(address);

            String safeEndpoint = endpoint.startsWith("/") ? endpoint : "/" + endpoint;
            String jsonPayload = objectMapper.writeValueAsString(payload);
            byte[] payloadBytes = jsonPayload.getBytes(StandardCharsets.UTF_8);

            String request =
                    method
                            + " "
                            + safeEndpoint
                            + " HTTP/1.1\r\n"
                            + "Host: localhost\r\n"
                            + "Accept: application/json\r\n"
                            + "Content-Type: application/json\r\n"
                            + "Content-Length: "
                            + payloadBytes.length
                            + "\r\n"
                            + "Connection: close\r\n"
                            + "\r\n";

            OutputStream out = Channels.newOutputStream(channel);
            out.write(request.getBytes(StandardCharsets.UTF_8));
            out.write(payloadBytes);
            out.flush();

            String rawResponse = this.readResponse(channel);
            return this.parseResponse(rawResponse);
        }
    }

    /**
     * Reads the complete response from the socket channel.
     *
     * @param channel the socket channel to read from
     * @return the response body as a string
     * @throws IOException if an I/O error occurs
     */
    @SuppressForbidden(reason = "Unix domain socket reading required for Engine communication")
    private String readResponse(SocketChannel channel) throws IOException {
        StringBuilder rawResponse = new StringBuilder();

        try (InputStream in = Channels.newInputStream(channel)) {
            byte[] buffer = new byte[BUFFER_SIZE];
            int bytesRead;

            while ((bytesRead = in.read(buffer)) != -1) {
                rawResponse.append(new String(buffer, 0, bytesRead, StandardCharsets.UTF_8));
            }
        }

        if (rawResponse.isEmpty()) {
            throw new IOException("Empty response from Engine");
        }

        return rawResponse.toString();
    }

    private RestResponse parseResponse(String rawResponse) {

        // 1. Split headers and body
        String[] parts = rawResponse.split("\r\n\r\n", 2);
        String headers = parts[0];
        String body = parts.length > 1 ? parts[1] : "";

        // 2. Extract Real HTTP Status Code
        int httpStatus = 500;
        try {
            String statusLine = headers.split("\r\n")[0];
            String[] statusParts = statusLine.split(" ");
            if (statusParts.length >= 2) {
                httpStatus = Integer.parseInt(statusParts[1]);
            }
        } catch (Exception e) {
            logger.warn(Constants.W_LOG_ENGINE_STATUS_LINE_PARSE_FAILED);
            logger.debug(Constants.D_LOG_ENGINE_RESPONSE_HEADERS, headers);
        }

        // 3. Parse JSON Body
        try {
            if (body.trim().isEmpty()) {
                return new RestResponse("Empty body received from Engine", httpStatus);
            }

            JsonNode jsonResponse = objectMapper.readTree(body);
            String message = body;

            if (jsonResponse.has("message")) {
                message = jsonResponse.get("message").asText();
            } else if (jsonResponse.has("error")) {
                message = jsonResponse.get("error").asText();
            } else if (jsonResponse.has("result")) {
                message = jsonResponse.get("result").toString();
            }

            return new RestResponse(message, httpStatus);

        } catch (Exception e) {
            logger.warn(Constants.W_LOG_ENGINE_JSON_PARSE_FAILED);
            logger.debug(Constants.D_LOG_ENGINE_RESPONSE_BODY, body);
            return new RestResponse(body, httpStatus);
        }
    }

    /**
     * Gets the configured socket path.
     *
     * @return the socket path
     */
    public String getSocketPath() {
        return this.socketPath;
    }
}
