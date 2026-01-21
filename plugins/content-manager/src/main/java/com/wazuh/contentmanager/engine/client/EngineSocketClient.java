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
import java.net.StandardProtocolFamily;
import java.net.UnixDomainSocketAddress;
import java.nio.channels.Channels;
import java.nio.channels.SocketChannel;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import com.wazuh.contentmanager.rest.model.RestResponse;

/**
 * Client for communicating with the Wazuh Engine through a Unix domain socket.
 *
 * <p>This client handles JSON-based HTTP communication over a Unix socket. Each request opens a new
 * connection that is closed after receiving the response.
 */
public record EngineSocketClient(String socketPath) {
    private static final Logger logger = LogManager.getLogger(EngineSocketClient.class);
    private static final String DEFAULT_SOCKET_PATH =
            "/usr/share/wazuh-indexer/engine/sockets/engine-api.sock";
    private static final int BUFFER_SIZE = 4096;
    private static final ObjectMapper objectMapper = new ObjectMapper();

    /** Creates a EngineSocketClient with the default socket path. */
    public EngineSocketClient() {
        this(DEFAULT_SOCKET_PATH);
    }

    /**
     * Creates a EngineSocketClient with a custom socket path.
     *
     * @param socketPath the path to the Unix domain socket
     */
    public EngineSocketClient {}

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
            String errorMsg = "Socket file not found at " + this.socketPath;
            logger.error(errorMsg);
            return new RestResponse(errorMsg, 500);
        }

        try {
            UnixDomainSocketAddress address = UnixDomainSocketAddress.of(socketFile);

            try (SocketChannel channel = SocketChannel.open(StandardProtocolFamily.UNIX)) {
                channel.connect(address);

                // Serialize the payload
                String jsonPayload = objectMapper.writeValueAsString(payload);
                byte[] payloadBytes = jsonPayload.getBytes(StandardCharsets.UTF_8);

                // Build HTTP request
                String request =
                        method
                                + " "
                                + endpoint
                                + " HTTP/1.1\r\n"
                                + "Host: localhost\r\n"
                                + "Content-Type: application/json\r\n"
                                + "Content-Length: "
                                + payloadBytes.length
                                + "\r\n"
                                + "Connection: close\r\n"
                                + "\r\n";

                // Use Channels API for writing
                try (OutputStream out = Channels.newOutputStream(channel)) {
                    out.write(request.getBytes(StandardCharsets.UTF_8));
                    out.write(payloadBytes);
                    out.flush();
                }

                // Read response
                String responseBody = this.readResponse(channel);

                // Parse the response
                return this.parseResponse(responseBody);

            } catch (IOException e) {
                String errorMsg = "Error communicating with Engine socket: " + e.getMessage();
                logger.error(errorMsg, e);
                return new RestResponse(errorMsg, 500);
            }

        } catch (Exception e) {
            String errorMsg = "Failed to connect to Engine socket: " + e.getMessage();
            logger.error(errorMsg, e);
            return new RestResponse(errorMsg, 503);
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

        // Split headers from body
        String[] parts = rawResponse.toString().split("\r\n\r\n", 2);
        if (parts.length < 2) {
            throw new IOException("Invalid HTTP response format");
        }

        return parts[1];
    }

    /**
     * Parses the JSON response body into a RestResponse object.
     *
     * @param responseBody the JSON response body
     * @return a RestResponse with status and message
     */
    private RestResponse parseResponse(String responseBody) {
        try {
            JsonNode jsonResponse = objectMapper.readTree(responseBody);

            // Extract status and message from the response
            int status = jsonResponse.has("status") ? jsonResponse.get("status").asInt(200) : 200;
            String message =
                    jsonResponse.has("message") ? jsonResponse.get("message").asText() : responseBody;

            return new RestResponse(message, status);

        } catch (Exception e) {
            logger.warn("Failed to parse Engine response as JSON: {}", e.getMessage());
            // If parsing fails, return the raw response
            return new RestResponse(responseBody, 200);
        }
    }

    /**
     * Gets the configured socket path.
     *
     * @return the socket path
     */
    @Override
    public String socketPath() {
        return this.socketPath;
    }
}
