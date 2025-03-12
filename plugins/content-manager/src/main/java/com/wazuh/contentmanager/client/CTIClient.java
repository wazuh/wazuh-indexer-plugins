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

import com.wazuh.contentmanager.util.Privileged;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.hc.core5.http.Header;
import org.apache.hc.core5.http.HttpResponse;
import org.apache.hc.core5.http.Method;

import java.io.*;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * CTIClient is a singleton class responsible for interacting with the CTI (Cyber Threat
 * Intelligence) API. It extends HttpClient to handle HTTP requests.
 */
public class CTIClient extends HttpClient {
    private static CTIClient instance;

    private static final String apiUrl =
            PluginSettings.getInstance().getCtiBaseUrl()
                    + "/catalog/contexts/vd_1.0.0/consumers/vd_4.8.0";
    private static final String CONTENT_CHANGES_ENDPOINT = "/changes";
    /**
     * Private constructor to enforce singleton pattern. Initializes the HTTP client with the CTI API
     * base URL.
     */
    protected CTIClient() {
        super(URI.create(apiUrl));
    }

    /**
     * Retrieves the singleton instance of CTIClient. Ensures thread-safe lazy initialization.
     *
     * @return The singleton instance of CTIClient.
     */
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

    /**
     * Fetches content changes from the CTI API.
     *
     * @param queryParameters A map containing query parameters to filter the request.
     * @return A SimpleHttpResponse containing the response from the API.
     */
    public SimpleHttpResponse getChanges(Map<String, String> queryParameters) {
        return sendRequest(Method.GET, CONTENT_CHANGES_ENDPOINT, null, queryParameters, (Header) null);
    }

    /**
     * Fetches the entire CTI catalog from the API.
     *
     * @return A SimpleHttpResponse containing the response from the API.
     */
    public SimpleHttpResponse getCatalog() {
        return sendRequest(Method.GET, null, null, null, (Header) null);
    }

    /**
     * Downloads the CTI snapshot into the /tmp file.
     *
     * @param snapshotURI It will have the URI used for the download, at the moment that URI is hardcoded.
     */
    public SimpleHttpResponse downloadSnapshot(String snapshotURI) {
        try {
            URI uri = new URI("https://cti.wazuh.com/store/contexts/vd_1.0.0/consumers/vd_4.8.0/1432540_1741603172.zip");

            //This needs to be changed once the Base Uri is changed in PluginSettings
            HttpClient con = new HttpClient(uri);
            SimpleHttpResponse res = con.sendRequest(Method.GET, null, null, null, (Header) null);

            if (res != null && res.getBodyBytes() != null) {
                try (InputStream in = new ByteArrayInputStream(res.getBodyBytes());
                     FileOutputStream fos = new FileOutputStream("/tmp/1432540_1741603172.zip")) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = in.read(buffer)) != -1) {
                        fos.write(buffer, 0, bytesRead);
                    }
                } catch (IOException e) {
                    throw new RuntimeException(e);
                }
            }
            return res;

        } catch (URISyntaxException e) {
            throw new RuntimeException(e);
        }
    }

}
