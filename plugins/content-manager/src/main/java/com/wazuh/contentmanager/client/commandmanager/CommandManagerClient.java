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
package com.wazuh.contentmanager.client.commandmanager;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;

import java.net.URI;
import java.util.Map;

import com.wazuh.contentmanager.client.HttpClient;
import com.wazuh.contentmanager.settings.PluginSettings;

public class CommandManagerClient extends HttpClient {
    private static volatile CommandManagerClient instance;
    public static final String BASE_COMMAND_MANAGER_URI = "/_plugins/_command_manager";
    public static final String POST_COMMAND_ENDPOINT = "/commands";

    private CommandManagerClient() {
        super(URI.create(PluginSettings.getInstance().getClusterBaseUrl() + BASE_COMMAND_MANAGER_URI));
    }

    public static CommandManagerClient getInstance() {
        if (instance == null) {
            synchronized (CommandManagerClient.class) {
                if (instance == null) {
                    instance = new CommandManagerClient();
                }
            }
        }
        return instance;
    }

    public SimpleHttpResponse postCommand(String requestBody) {
        return sendRequest("POST", POST_COMMAND_ENDPOINT, requestBody, null, (Header) null);
    }
}
