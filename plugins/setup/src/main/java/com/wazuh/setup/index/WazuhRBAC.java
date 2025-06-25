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
package com.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;

/** Class to handle indexing of RBAC related resources */
public class WazuhRBAC {

    public static final String DEFAULT_USERS_FILENAME = "default-rbac-users.json";
    public static final String DEFAULT_USER_ID = "wazuh";
    public static final String RBAC_INDEX_NAME = "wazuh-internal-users";
    private final Client client;

    private static final Logger log = LogManager.getLogger(WazuhRBAC.class);

    /**
     * Constructor for the RBAC index handling class
     *
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
    public boolean documentExists(String indexName, String documentId) {
        try {
            return this.client.get(new GetRequest(indexName, documentId)).actionGet().isExists();
        } catch (IllegalStateException e) {
            log.error("Failed to get internal user [{}]: {}", documentId, e.getMessage());
        }
        return false;
    }

    /** Update "created_at" field with current date */
    private void updateCreatedAt() {
        try (XContentBuilder xContentBuilder = XContentFactory.jsonBuilder()) {
            this.client.update(
                    new UpdateRequest(RBAC_INDEX_NAME, DEFAULT_USER_ID)
                            .doc(
                                    xContentBuilder
                                            .startObject()
                                            .startObject("user")
                                            .field("created_at", Instant.now().toString())
                                            .endObject()
                                            .endObject()),
                    new ActionListener<>() {
                        @Override
                        public void onResponse(UpdateResponse updateResponse) {
                            log.info("Successfully updated created_at field");
                        }

                        @Override
                        public void onFailure(Exception e) {
                            log.error(
                                    "Failed to update created_at field for user id {}: {}",
                                    DEFAULT_USER_ID,
                                    e.getMessage());
                        }
                    });
        } catch (IOException e) {
            log.error("Failed to create JSON object: {}", e.getMessage());
        }
    }

    /** Indexes the default internal users data */
    public void initialize() {
        if (documentExists(RBAC_INDEX_NAME, DEFAULT_USER_ID)) {
            return;
        }

        BytesReference bytesReference;
        try (InputStream is = getResourceAsStream(DEFAULT_USERS_FILENAME)) {
            bytesReference = new BytesArray(is.readAllBytes());
        } catch (IOException | OutOfMemoryError | NullPointerException | SecurityException e) {
            log.error(
                    "Failed to get default internal users from file [{}]: {}",
                    DEFAULT_USERS_FILENAME,
                    e.getMessage());
            return;
        }

        IndexRequest indexRequest =
                new IndexRequest(RBAC_INDEX_NAME)
                        .index(RBAC_INDEX_NAME)
                        .id(DEFAULT_USER_ID)
                        .source(bytesReference, MediaTypeRegistry.JSON)
                        .create(true);

        this.client.index(
                indexRequest,
                new ActionListener<>() {
                    @Override
                    public void onResponse(IndexResponse indexResponse) {
                        log.info("Default internal users created: {}", indexResponse.getResult());
                        updateCreatedAt();
                    }

                    @Override
                    public void onFailure(Exception e) {
                        log.error("Failed to index internal users: {}", e.getMessage());
                    }
                });
    }

    /**
     * This is extracted to a method for ease of mocking
     *
     * @param filename The filename of the resource to be loaded
     * @return An InputStream with the contents of the file
     */
    public InputStream getResourceAsStream(String filename) {
        return WazuhRBAC.class.getClassLoader().getResourceAsStream(filename);
    }
}
