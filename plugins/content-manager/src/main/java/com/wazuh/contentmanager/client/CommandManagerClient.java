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

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.*;
import org.apache.hc.core5.http.message.BasicHeader;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;

import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * CommandManagerClient is a singleton class responsible for managing HTTP communication with the
 * Command Manager API.
 */
public class CommandManagerClient extends HttpClient {
    private static final Logger log = LogManager.getLogger(CommandManagerClient.class);

    private static volatile CommandManagerClient instance;

    /** Base Content Manager Plugin API endpoint. */
    public static final String BASE_COMMAND_MANAGER_URI = "/_plugins/_command_manager";

    /** Endpoint to post new commands. */
    public static final String POST_COMMAND_ENDPOINT = "/commands";

    /** Private constructor to initialize the CommandManagerClient with the base API URI. */
    private CommandManagerClient() throws HttpClientException {
        super(URI.create(PluginSettings.getInstance().getClusterBaseUrl() + BASE_COMMAND_MANAGER_URI));
    }

    /**
     * Returns the singleton instance of CommandManagerClient. Uses double-checked locking to ensure
     * thread safety.
     *
     * @return The singleton instance of CommandManagerClient.
     */
    public static CommandManagerClient getInstance() throws HttpClientException {
        if (instance == null) {
            synchronized (CommandManagerClient.class) {
                if (instance == null) {
                    instance = new CommandManagerClient();
                }
            }
        }
        return instance;
    }

    /**
     * Sends a POST request to execute a command via the Command Manager API.
     *
     * @param requestBody The JSON request body containing the command details.
     * @throws HttpClientException If an error occurs while sending the request or processing the
     *     response.
     */
    public void postCommand(String requestBody) throws HttpClientException {
        Header header = new BasicHeader(HttpHeaders.CONTENT_TYPE, ContentType.APPLICATION_JSON);
        SimpleHttpResponse response =
                this.sendRequest(Method.POST, POST_COMMAND_ENDPOINT, requestBody, null, header);
        this.handlePostResponse(response);
    }

    /**
     * Handles the response of the POST request to the Command Manager endpoint.
     *
     * @param response The response from the POST request
     * @throws HttpClientException If an error occurs while handling the response.
     */
    private void handlePostResponse(SimpleHttpResponse response) throws HttpClientException {
        if (response == null) {
            log.error("No reply from server");
        } else {
            switch (response.getCode()) {
                case HttpStatus.SC_OK:
                    log.info("Received OK response: {}", response.getBody().toString());
                    break;
                case HttpStatus.SC_CLIENT_ERROR:
                    throw new HttpClientException("Client error: {}" + response.getBody().toString());
                case HttpStatus.SC_SERVER_ERROR:
                    throw new HttpClientException("Server error: {}" + response.getBody().toString());
                default:
                    log.warn("Unexpected response code: {}", response.getCode());
            }
        }
    }
}
