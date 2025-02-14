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
package com.wazuh.contentmanager.client.cti;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;

import java.net.URI;
import java.util.Map;

import com.wazuh.contentmanager.client.HttpClient;
import com.wazuh.contentmanager.settings.PluginSettings;

public class CTIClient extends HttpClient {
    private static CTIClient instance;

    private static final String apiUrl =
            PluginSettings.getInstance().getCtiBaseUrl()
                    + "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";

    protected CTIClient() {
        super(URI.create(apiUrl));
    }

    public static CTIClient getInstance() {
        if (instance == null) {
            synchronized (CTIClient.class) {
                if (instance == null) {
                    instance = new CTIClient();
                }
            }
        }
        return instance;
    }

    public SimpleHttpResponse getChanges() {
        String endpoint = "/changes";
        return sendRequest("GET", endpoint, null, null, (Header) null);
    }

    public SimpleHttpResponse getCatalog() {
        return sendRequest("GET", null, null, null, (Header) null);
    }
}
