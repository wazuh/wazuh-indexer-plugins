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
package com.wazuh.contentmanager.cti.catalog.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.transport.client.Client;

import java.util.Map;

/** Utility class for common OpenSearch index operations. */
public final class IndexHelper {

    private static final Logger log = LogManager.getLogger(IndexHelper.class);

    private IndexHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Retrieves a document's source by ID from an index.
     *
     * @param client The OpenSearch client.
     * @param index The index name.
     * @param id The document ID.
     * @return The document source as a Map, or null if not found.
     */
    public static Map<String, Object> getDocumentSource(Client client, String index, String id) {
        try {
            GetResponse response = client.prepareGet(index, id).get();
            if (response.isExists()) {
                return response.getSourceAsMap();
            } else {
                log.info("Document [{}] not found in index [{}]", id, index);
            }
        } catch (Exception e) {
            log.info("Error retrieving document [{}] from index [{}]: {}", id, index, e.getMessage());
        }
        return null;
    }

    /**
     * Checks if an index exists.
     *
     * @param client The OpenSearch client.
     * @param indexName The index name to check.
     * @return true if the index exists, false otherwise.
     */
    public static boolean indexExists(Client client, String indexName) {
        try {
            return client.admin().indices().prepareExists(indexName).get().isExists();
        } catch (Exception e) {
            log.error("Error checking if index [{}] exists: {}", indexName, e.getMessage());
            return false;
        }
    }
}
