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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.PlainActionFuture;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.action.update.UpdateResponse;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.setup.utils.IndexTemplateUtils;

/** Class to manage the Command Manager index and index template. */
public class PolicyIndex {

    private static final Logger log = LogManager.getLogger(PolicyIndex.class);

    private final Client client;
    private final ClusterService clusterService;
    public static final String POLICY_ID = "wazuh-alerts-rollover-policy";

    public final String ISM_INDEX = ".opendistro-ism-config";
    public final String ISM_TEMPLATE_NAME = "opendistro-ism-config";

    public static BytesArray POLICY;

    /**
     * Default constructor
     *
     * @param client OpenSearch client.
     * @param clusterService OpenSearch cluster service.
     */
    public PolicyIndex(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
        try {
            POLICY =
                    new BytesArray(
                            Objects.requireNonNull(
                                            PolicyIndex.class.getClassLoader().getResourceAsStream(POLICY_ID + ".json"))
                                    .readAllBytes());
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Checks if the command index exists.
     *
     * @return whether the internal Command Manager's index exists.
     */
    public boolean iSMIndexExists() {
        return this.clusterService.state().routingTable().hasIndex(ISM_INDEX);
    }

    private void updateCreatedAt() {
        long timestamp = Instant.now().toEpochMilli();
        try (XContentBuilder xContentBuilder = XContentFactory.jsonBuilder()) {
            client.update(
                    new UpdateRequest(ISM_INDEX, POLICY_ID)
                            .doc(
                                    xContentBuilder
                                            .startObject()
                                            .startObject("policy")
                                            .startArray("ism_template")
                                            .startObject()
                                            .field("last_updated_time", timestamp)
                                            .endObject()
                                            .endArray()
                                            .field("last_updated_time", timestamp)
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
                                    POLICY_ID,
                                    e.getMessage());
                        }
                    });
        } catch (IOException e) {
            log.error("Failed to create JSON object: {}", e.getMessage());
        }
    }

    /** Indexes an array of documents asynchronously. */
    public void indexPolicy() {

        // assert !iSMIndexExists();
        // if( iSMIndexExists()) {
        //    log.info("Pepitoooou");
        //    return;
        // }

        IndexRequest indexRequest =
                new IndexRequest(ISM_INDEX)
                        .index(ISM_INDEX)
                        .id(POLICY_ID)
                        .source(POLICY, MediaTypeRegistry.JSON);

        // .create(true);

        PlainActionFuture<IndexResponse> future = new PlainActionFuture<>();
        client.index(indexRequest, future);
        IndexResponse response = null;
        try {
            response = future.get(5, TimeUnit.SECONDS);
        } catch (InterruptedException | TimeoutException | ExecutionException e) {
            log.error("Failed to index Wazuh Rollover Policy: {}", e.getMessage());
            return;
        }
        assert response != null;
        log.info("Successfully indexed Wazuh Rollover Policy: {}", response.getResult());
    }

    /** Puts the .opendistro-ism-config template into the cluster and creates the index */
    public void putISMTemplate() {
        if (iSMIndexExists()) {
            log.info("{} Index exists, skipping", ISM_INDEX);
            return;
        }
        Map<String, Object> template = null;
        log.info("Attempting to create {} index", ISM_INDEX);
        try {
            template = IndexTemplateUtils.fromFile(ISM_TEMPLATE_NAME + ".json");
            PlainActionFuture<CreateIndexResponse> future = new PlainActionFuture<>();
            client
                    .admin()
                    .indices()
                    .create(
                            new CreateIndexRequest(ISM_INDEX)
                                    .mapping(IndexTemplateUtils.get(template, "mappings"))
                                    .settings(IndexTemplateUtils.get(template, "settings")),
                            future);
            future.get(5, TimeUnit.SECONDS);
            log.info("Successfully created {} index", ISM_INDEX);
        } catch (IOException | ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Failed loading ISM index template from file: {}", e.getMessage());
        }
    }
}
