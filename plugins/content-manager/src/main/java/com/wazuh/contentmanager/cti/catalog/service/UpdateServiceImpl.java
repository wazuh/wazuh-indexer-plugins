/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.JsonNode;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.get.GetResponse;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Changes;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Offset;
import com.wazuh.contentmanager.cti.catalog.model.Space;

/** Service responsible for keeping the catalog content up-to-date. */
public class UpdateServiceImpl extends AbstractService implements UpdateService {
    private static final Logger log = LogManager.getLogger(UpdateServiceImpl.class);

    private final ConsumersIndex consumersIndex;
    private final Map<String, ContentIndex> indices;
    private final String context;
    private final String consumer;

    /**
     * Constructs a new UpdateServiceImpl.
     *
     * @param context The context string (e.g., catalog ID) for the consumer.
     * @param consumer The name of the consumer entity.
     * @param client The API client used to fetch changes.
     * @param consumersIndex The index responsible for storing consumer state (offsets).
     * @param indices A map of content type to {@link ContentIndex} managers.
     */
    public UpdateServiceImpl(
            String context,
            String consumer,
            ApiClient client,
            ConsumersIndex consumersIndex,
            Map<String, ContentIndex> indices) {
        if (this.client != null) {
            this.client.close();
        }

        this.client = client;
        this.consumersIndex = consumersIndex;
        this.indices = indices;
        this.context = context;
        this.consumer = consumer;
    }

    /**
     * Performs a content update within the specified offset range.
     *
     * <p>Implementation details: 1. Fetches the changes JSON from the API for the given range. 2.
     * Parses the response into {@link Changes} and {@link Offset} objects. 3. Iterates through
     * offsets. 4. Delegates specific operations to {@link #applyOffset(Offset)}. 5. Updates the
     * {@link LocalConsumer} record in the index with the last successfully applied offset.
     *
     * <p>If an exception occurs, the consumer state is reset to prevent data corruption or stuck
     * states.
     */
    @Override
    public void update(long fromOffset, long toOffset) {
        log.info(
                "Starting content update for consumer [{}] from [{}] to [{}]",
                this.consumer,
                fromOffset,
                toOffset);
        try {
            SimpleHttpResponse response =
                    this.client.getChanges(this.context, this.consumer, fromOffset, toOffset);
            if (response.getCode() != 200) {
                log.error("Failed to fetch changes: {} {}", response.getCode(), response.getBodyText());
                return;
            }

            Changes changes = this.mapper.readValue(response.getBodyBytes(), Changes.class);
            long lastAppliedOffset = fromOffset;

            for (Offset offset : changes.get()) {
                this.applyOffset(offset);
                lastAppliedOffset = offset.getOffset();
            }

            // Update consumer state
            LocalConsumer consumer = new LocalConsumer(this.context, this.consumer);

            // Properly handle the GetResponse to check if the document exists before parsing
            GetResponse getResponse = this.consumersIndex.getConsumer(this.context, this.consumer);
            LocalConsumer current =
                    (getResponse != null && getResponse.isExists())
                            ? this.mapper.readValue(getResponse.getSourceAsString(), LocalConsumer.class)
                            : consumer;

            LocalConsumer updated =
                    new LocalConsumer(
                            this.context,
                            this.consumer,
                            lastAppliedOffset,
                            current.getRemoteOffset(),
                            current.getSnapshotLink());
            this.consumersIndex.setConsumer(updated);

            log.info("Successfully updated consumer [{}] to offset [{}]", consumer, lastAppliedOffset);
        } catch (Exception e) {
            log.error("Error during content update: {}", e.getMessage(), e);
            this.resetConsumer();
        }
    }

    /**
     * Applies a specific change offset to the appropriate content index.
     *
     * @param offset The {@link Offset} containing the type of change and data.
     * @throws Exception If the indexing operation fails.
     */
    private void applyOffset(Offset offset) throws Exception {
        String id = offset.getResource();
        ContentIndex index;
        // TODO: Handle spaces properly
        String space = Space.STANDARD.toString();

        switch (offset.getType()) {
            case CREATE:
                if (offset.getPayload() != null) {
                    JsonNode payload = this.mapper.valueToTree(offset.getPayload());
                    if (payload.has("type")) {
                        String type = payload.get("type").asText();

                        index = this.indices.get(type);
                        if (index != null) {
                            index.create(id, payload, Space.STANDARD.toString());
                        } else {
                            log.warn("No index mapped for type [{}]", type);
                        }
                    }
                }
                break;
            case UPDATE:
                index = this.findIndexForId(id);
                index.update(id, offset.getOperations(), space);
                break;
            case DELETE:
                index = this.findIndexForId(id);
                index.delete(id);
                break;
            default:
                log.warn("Unsupported JSON patch operation [{}]", offset.getType());
                break;
        }
    }

    /**
     * Locates the {@link ContentIndex} that contains the document with the specified ID.
     *
     * @param id The document ID to search for.
     * @return The matching {@link ContentIndex}.
     * @throws ResourceNotFoundException If no {@link ContentIndex} contains the document with the
     *     specified ID.
     */
    private ContentIndex findIndexForId(String id) throws ResourceNotFoundException {
        // When it is a policy document, it must be treated special, since the id policy doesn't exist
        if ("policy".equals(id)) {
            ContentIndex policyIndex = this.indices.get("policy");
            if (policyIndex != null) {
                return policyIndex;
            }
            throw new ResourceNotFoundException("Policy index not found.");
        }

        for (ContentIndex index : this.indices.values()) {
            if (index.exists(id)) {
                return index;
            }
        }
        throw new ResourceNotFoundException(
                "Document with ID '" + id + "' could not be found in any ContentIndex.");
    }

    /** Resets the local consumer offset to 0. */
    private void resetConsumer() {
        log.info("Resetting consumer [{}] offset to 0 due to update failure.", this.consumer);
        try {
            LocalConsumer reset = new LocalConsumer(this.context, this.consumer, 0, 0, "");
            this.consumersIndex.setConsumer(reset);
        } catch (Exception e) {
            log.error("Failed to reset consumer: {}", e.getMessage());
        }
    }
}
