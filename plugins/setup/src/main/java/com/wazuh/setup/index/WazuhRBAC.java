package com.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.client.Client;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.MediaTypeRegistry;

import java.io.IOException;
import java.util.Objects;

/**
 * Class to handle indexing of RBAC related resources
 */
public class WazuhRBAC {

    private static final String DEFAULT_USERS_FILENAME = "default-rbac-users.json";
    private static final String DEFAULT_USER_ID = "1";
    private static final String RBAC_INDEX_NAME = "wazuh-internal-users";
    private final Client client;

    private static final Logger log = LogManager.getLogger(WazuhRBAC.class);

    /**
     * Constructor for the RBAC index handling class
     * @param client The cluster client that performs indexing and search operations
     */
    public WazuhRBAC(Client client) {
        this.client = client;
    }

    /**
     * Returns whether the document exists
     *
     * @param indexName The index to look into
     * @param documentId The document to look for
     * @return Return true if document exists
     */
    private boolean documentExists(String indexName, String documentId) {
        try {
            return client.get(new GetRequest(indexName, documentId)).actionGet().isExists();
        } catch (IllegalStateException e) {
            log.error("Failed to get internal user [{}]: {}", documentId, e.getMessage());
        }
        return false;
    }

    /**
     * Indexes the default internal users data
     */
    public void indexRBACUsers() {
        if (documentExists(RBAC_INDEX_NAME, DEFAULT_USER_ID)) {
            return;
        }

        BytesReference bytesReference =
            null;
        try {
            bytesReference = new BytesArray(
                Objects.requireNonNull(
                        getClass().getClassLoader().getResourceAsStream(DEFAULT_USERS_FILENAME))
                    .readAllBytes());
        } catch (IOException | OutOfMemoryError | NullPointerException | SecurityException e) {
            log.error("Failed to get default internal users from file [{}]: {}", DEFAULT_USERS_FILENAME, e.getMessage());
        }

        IndexRequest indexRequest =
            new IndexRequest(RBAC_INDEX_NAME)
                .index(RBAC_INDEX_NAME)
                .id("1")
                .source(bytesReference, MediaTypeRegistry.JSON)
                .create(true);

        client.index(indexRequest, new ActionListener<>() {
            @Override
            public void onResponse(IndexResponse indexResponse) {
                log.info("Default internal users created: {}", indexResponse.getResult());
            }

            @Override
            public void onFailure(Exception e) {
                log.error("Failed to index internal users: {}", e.getMessage());

            }
        });
    }
}
