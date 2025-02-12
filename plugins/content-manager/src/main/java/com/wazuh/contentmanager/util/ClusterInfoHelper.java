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
        return settings.getAsBoolean("xpack.security.http.ssl.enabled", false) ||
                settings.getAsBoolean("plugins.security.ssl.http.enabled", false);
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
