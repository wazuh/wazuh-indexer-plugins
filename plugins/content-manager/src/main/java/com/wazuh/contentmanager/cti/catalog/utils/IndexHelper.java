package com.wazuh.contentmanager.cti.catalog.utils;

import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.transport.client.Client;

/**
 * Utility class for common OpenSearch index operations.
 */
public final class IndexHelper {

    private static final Logger log = LogManager.getLogger(IndexHelper.class);

    private IndexHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Retrieves a document's source by ID from an index.
     *
     * @param client The OpenSearch client.
     * @param index  The index name.
     * @param id     The document ID.
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
     * @param client    The OpenSearch client.
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
