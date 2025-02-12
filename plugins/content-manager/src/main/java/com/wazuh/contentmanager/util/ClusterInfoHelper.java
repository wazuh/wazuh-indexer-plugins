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
package com.wazuh.contentmanager.util;

import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Settings;

public class ClusterInfoHelper {
    /**
     * Checks if the cluster is using HTTPS.
     *
     * @return true if HTTPS is enabled, false otherwise.
     */
    public static boolean isHttpsEnabled(ClusterService clusterService) {
        Settings settings = clusterService.getSettings();

        // Check if security plugins have HTTPS enabled
        return settings.getAsBoolean("xpack.security.http.ssl.enabled", false)
                || settings.getAsBoolean("plugins.security.ssl.http.enabled", false);
    }

    /**
     * Retrieves the cluster base URL with the correct protocol.
     *
     * @return Cluster base URL with HTTP or HTTPS.
     */
    public static String getClusterBaseUrl(ClusterService clusterService) {
        DiscoveryNode node = clusterService.state().nodes().getClusterManagerNode();
        String protocol = isHttpsEnabled(clusterService) ? "https" : "http";
        String clusterIp = "127.0.0.1:9200";
        if (node != null) {
            // Get the address in format <IP>:<PORT>.
            clusterIp = node.getAddress().toString();
        }
        return protocol + "://" + clusterIp;
    }
}
