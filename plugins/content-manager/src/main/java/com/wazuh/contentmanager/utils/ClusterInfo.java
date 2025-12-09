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

import org.opensearch.action.admin.cluster.health.ClusterHealthResponse;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequest;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
import org.opensearch.transport.client.Client;
import org.opensearch.cluster.health.ClusterHealthStatus;

/**
 * ClusterInfo provides utility methods for retrieving cluster-related information, such as
 * security settings and the cluster base URL.
 */
public class ClusterInfo {

    /**
     * Checks if a given index is ready for operations.
     *
     * @param client OpenSearch client.
     * @param index index name to check.
     * @return true if the index is ready, false otherwise.
     */
    public static boolean indexStatusCheck(Client client, String index) {
        ClusterHealthResponse response =
            client.admin().cluster().prepareHealth().setIndices(index).setWaitForYellowStatus().get();
        return response.getStatus() != ClusterHealthStatus.RED;
    }

    /**
     * Checks whether the given index exists.
     *
     * @param client OpenSearch client.
     * @param index index name to check its existence for.
     * @return true if the index exists, false otherwise.
     */
    public static boolean indexExists(Client client, String index) {
        IndicesExistsRequest request = new IndicesExistsRequest(index);
        IndicesExistsResponse response = client.admin().indices().exists(request).actionGet();
        return response.isExists();
    }
}
