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

import com.wazuh.contentmanager.settings.PluginSettings;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;

import com.wazuh.contentmanager.client.HttpClient;

import java.net.URI;

public class CommandManagerClient extends HttpClient {
    private static volatile CommandManagerClient instance;
    public static final String BASE_COMMAND_MANAGER_ENDPOINT = "/_plugins/_command_manager";
    public static final String CREATE_COMMAND_ENDPOINT = BASE_COMMAND_MANAGER_ENDPOINT + "/commands";

    private CommandManagerClient() {
        super();
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

    public SimpleHttpResponse sendCommand(String requestBody, Header... headers) {
        String uri = PluginSettings.getInstance().getCommandManagerBaseUrl() + CREATE_COMMAND_ENDPOINT;
        return sendRequest("POST", URI.create(uri), requestBody, null, headers);
    }
}
