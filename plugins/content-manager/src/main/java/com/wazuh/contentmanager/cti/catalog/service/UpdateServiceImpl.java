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
package com.wazuh.contentmanager.cti.catalog.service;

import com.google.gson.Gson;
import com.google.gson.JsonObject;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Changes;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Offset;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;

import java.util.Map;

/**
 * Service responsible for keeping the catalog content up-to-date.
 */
public class UpdateServiceImpl extends AbstractService implements UpdateService {
    private static final Logger log = LogManager.getLogger(UpdateServiceImpl.class);

    private final ConsumersIndex consumersIndex;
    private final Map<String, ContentIndex> indices;
    private final String context;
    private final String consumerName;
    private final Gson gson;

    /**
     * Constructs a new UpdateServiceImpl.
     *
     * @param context        The context string (e.g., catalog ID) for the consumer.
     * @param consumerName   The name of the consumer entity.
     * @param client         The API client used to fetch changes.
     * @param consumersIndex The index responsible for storing consumer state (offsets).
     * @param indices        A map of content type to {@link ContentIndex} managers.
     */
    public UpdateServiceImpl(String context, String consumerName, ApiClient client, ConsumersIndex consumersIndex, Map<String, ContentIndex> indices) {
        if (this.client != null) {
            this.client.close();
        }

        this.client = client;
        this.consumersIndex = consumersIndex;
        this.indices = indices;
        this.context = context;
        this.consumerName = consumerName;
        this.gson = new Gson();
    }

    /**
     *
     * Performs a content update within the specified offset range.
     *
     * Implementation details:
     * 1. Fetches the changes JSON from the API for the given range.
     * 2. Parses the response into {@link Changes} and {@link Offset} objects.
     * 3. Iterates through offsets.
     * 4. Delegates specific operations to {@link #applyOffset(Offset)}.
     * 5. Updates the {@link LocalConsumer} record in the index with the last successfully applied offset.
     *
     * If an exception occurs, the consumer state is reset to prevent data corruption or stuck states.
     */
    @Override
    public void update(long fromOffset, long toOffset) {
        log.info("Starting content update for consumer [{}] from [{}] to [{}]", consumerName, fromOffset, toOffset);
        try {
            SimpleHttpResponse response = this.client.getChanges(context, consumerName, fromOffset, toOffset);
            if (response.getCode() != 200) {
                log.error("Failed to fetch changes: {} {}", response.getCode(), response.getBodyText());
                return;
            }

            try (XContentParser parser = XContentType.JSON.xContent().createParser(
                NamedXContentRegistry.EMPTY,
                DeprecationHandler.THROW_UNSUPPORTED_OPERATION,
                response.getBodyBytes())) {
                Changes changes = Changes.parse(parser);
                long lastAppliedOffset = fromOffset;

                for (Offset offset : changes.get()) {
                    applyOffset(offset);
                    lastAppliedOffset = offset.getOffset();
                }

                // Update consumer state
                LocalConsumer consumer = new LocalConsumer(context, consumerName);

                // Properly handle the GetResponse to check if the document exists before parsing
                GetResponse getResponse = consumersIndex.getConsumer(context, consumerName);
                LocalConsumer current = (getResponse != null && getResponse.isExists()) ?
                    this.mapper.readValue(getResponse.getSourceAsString(), LocalConsumer.class) : consumer;

                LocalConsumer updated = new LocalConsumer(context, consumerName, lastAppliedOffset, current.getRemoteOffset(), current.getSnapshotLink());
                consumersIndex.setConsumer(updated);

                log.info("Successfully updated consumer [{}] to offset [{}]", consumerName, lastAppliedOffset);
            }
        } catch (Exception e) {
            log.error("Error during content update: {}", e.getMessage(), e);
            resetConsumer();
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

        // Handle specific ID generation for policies
        if ("policy".equals(id)) {
            id = (this.context + "_" + this.consumerName);
        }

        switch (offset.getType()) {
            case CREATE:
                if (offset.getPayload() != null) {
                    JsonObject payload = gson.toJsonTree(offset.getPayload()).getAsJsonObject();
                    if (payload.has("type")) {
                        String type = payload.get("type").getAsString();
                        ContentIndex index = indices.get(type);
                        if (index != null) {
                            index.create(id, payload);
                        } else {
                            log.warn("No index mapped for type [{}]", type);
                        }
                    }
                }
                break;
            case UPDATE:
                ContentIndex index = findIndexForId(id);
                if (index != null) {
                    index.update(id, offset.getOperations());
                } else {
                    log.warn("Resource [{}] not found in any index for update.", id);
                }
                break;
            case DELETE:
                ContentIndex delIndex = findIndexForId(id);
                if (delIndex != null) {
                    delIndex.delete(id);
                }
                break;
        }
    }

    /**
     * Locates the {@link ContentIndex} that contains the document with the specified ID.
     *
     * @param id The document ID to search for.
     * @return The matching {@link ContentIndex}, or null if not found.
     */
    private ContentIndex findIndexForId(String id) {
        for (ContentIndex idx : indices.values()) {
            if (idx.exists(id)) {
                return idx;
            }
        }
        return null;
    }

    /**
     * Resets the local consumer offset to 0.
     */
    private void resetConsumer() {
        log.warn("Resetting consumer [{}] offset to 0 due to update failure.", consumerName);
        try {
            LocalConsumer reset = new LocalConsumer(context, consumerName, 0, 0, "");
            consumersIndex.setConsumer(reset);
        } catch (Exception e) {
            log.error("Failed to reset consumer: {}", e.getMessage());
        }
    }
}
