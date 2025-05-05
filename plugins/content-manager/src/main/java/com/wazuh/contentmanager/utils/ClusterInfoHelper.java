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
package com.wazuh.contentmanager.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;

import java.util.Locale;

/**
 * ClusterInfoHelper provides utility methods for retrieving cluster-related information, such as
 * security settings and the cluster base URL.
 */
public class ClusterInfoHelper {
    private static final Logger log = LogManager.getLogger(ClusterInfoHelper.class);

    /**
     * Checks if the OpenSearch cluster is using HTTPS for communication.
     *
     * @param clusterService The ClusterService instance providing cluster settings.
     * @return true if HTTPS is enabled, false otherwise.
     */
    public static boolean isHttpsEnabled(ClusterService clusterService) {
        Settings settings = clusterService.getSettings();

        // Check if security plugins have HTTPS enabled
        return settings.getAsBoolean("plugins.security.ssl.http.enabled", false)
                || settings.getAsBoolean("xpack.security.http.ssl.enabled", false);
    }

    /**
     * Retrieves the base URL of the OpenSearch cluster with the appropriate protocol (HTTP/HTTPS).
     *
     * @param clusterService The ClusterService instance providing cluster state and nodes.
     * @return The cluster base URL in the format "http(s)://[IP]:[PORT]".
     */
    public static String getClusterBaseUrl(ClusterService clusterService) {
        String protocol = ClusterInfoHelper.isHttpsEnabled(clusterService) ? "https" : "http";
        String host = "127.0.0.1";
        String port = "9200";
        if (clusterService.state().nodes().getClusterManagerNode() != null) {
            host = clusterService.getSettings().get("network.host", host);
            port = clusterService.getSettings().get("http.port", port);
        }
        return String.format(Locale.ROOT, "%s://%s:%s", protocol, host, port);
    }
}
