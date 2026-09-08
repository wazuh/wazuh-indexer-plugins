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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceNotFoundException;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.core.action.ActionListener;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Changes;
import com.wazuh.contentmanager.cti.catalog.model.Cve;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Offset;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/** Service responsible for keeping the catalog content up-to-date. */
public class UpdateServiceImpl extends AbstractService implements UpdateService {
    private static final Logger log = LogManager.getLogger(UpdateServiceImpl.class);
    private static final int FLUSH_EVERY_N_BATCHES = 10;

    private final ConsumersIndex consumersIndex;
    private final Map<String, ContentIndex> indices;
    private final String context;
    private final String consumer;
    private final String consumerType;
    private final String consumerUri;
    private final ContentIndex singleIndex;
    private final boolean cveCatalog;

    /**
     * Constructs a new UpdateServiceImpl.
     *
     * @param context The context string (e.g., catalog ID) for the consumer.
     * @param consumer The name of the consumer entity.
     * @param consumerType The consumer type identifier used as local document id.
     * @param consumerUri The full CTI consumer URL used to fetch remote changes.
     * @param client The API client used to fetch changes.
     * @param consumersIndex The index responsible for storing consumer state (offsets).
     * @param indices A map of content type to {@link ContentIndex} managers.
     */
    public UpdateServiceImpl(
            String context,
            String consumer,
            String consumerType,
            String consumerUri,
            ApiClient client,
            ConsumersIndex consumersIndex,
            Map<String, ContentIndex> indices) {
        super(client);
        this.consumersIndex = consumersIndex;
        this.indices = indices;
        this.context = context;
        this.consumer = consumer;
        this.consumerType = consumerType;
        this.consumerUri = consumerUri;
        this.singleIndex = indices.size() == 1 ? indices.values().iterator().next() : null;
        this.cveCatalog = this.singleIndex != null && indices.containsKey(Constants.KEY_CVES);
    }

    /**
     * Performs a content update within the specified offset range.
     *
     * <p>Implementation details: 1. Fetches the changes JSON from the API for the given range. 2.
     * Parses the response into {@link Changes} and {@link Offset} objects. 3. Iterates through
     * offsets. 4. Delegates specific operations to {@link #applyOffset(Offset)}. 5. Persists a
     * checkpoint to the {@link LocalConsumer} record after each successful batch so that progress
     * survives failures.
     *
     * <p>On failure the exception propagates to the caller without resetting the consumer offset,
     * allowing the next sync cycle to resume from the last checkpoint.
     */
    @Override
    public boolean update(long fromOffset, long toOffset) {
        log.debug(Constants.D_LOG_UPDATE_START, this.consumer, fromOffset, toOffset);
        try {
            GetResponse getResponse = this.consumersIndex.getConsumer(this.consumerType);
            LocalConsumer current =
                    (getResponse != null && getResponse.isExists())
                            ? this.mapper.readValue(getResponse.getSourceAsString(), LocalConsumer.class)
                            : new LocalConsumer(
                                    this.context, this.consumer, this.consumerType, this.consumerUri, true);

            String effectiveContext = this.firstNonBlank(current.getContext(), this.context);
            String effectiveName = this.firstNonBlank(current.getName(), this.consumer);
            String effectiveType = this.firstNonBlank(current.getType(), this.consumerType);
            String effectiveResource = this.firstNonBlank(current.getResource(), this.consumerUri);
            boolean effectiveIsPublic = current.isPublic();
            List<String> effectivePendingSyncPhases = current.getPendingSyncPhases();

            long currentFromOffset = fromOffset;
            long lastAppliedOffset = fromOffset;
            int batchCount = 0;

            while (currentFromOffset < toOffset) {
                long currentToOffset =
                        Math.min(
                                currentFromOffset + PluginSettings.getInstance().getMaxItemsPerBulk(), toOffset);

                SimpleHttpResponse response =
                        this.client.getChanges(this.consumerUri, currentFromOffset, currentToOffset);
                if (response.getCode() != 200) {
                    log.error(
                            "Failed to fetch changes from offset [{}] to [{}] with error code [{}]",
                            currentFromOffset,
                            currentToOffset,
                            response.getCode());
                    throw new RuntimeException(
                            "Failed to fetch changes for consumer ["
                                    + this.consumerType
                                    + "] (HTTP "
                                    + response.getCode()
                                    + ")");
                }

                Changes changes = this.mapper.readValue(response.getBodyBytes(), Changes.class);
                List<ContentIndex.UpdateTask> updateBatch = new ArrayList<>();

                for (Offset offset : changes.get()) {
                    try {
                        if (offset.getType() != Offset.Type.UPDATE && !updateBatch.isEmpty()) {
                            lastAppliedOffset = this.singleIndex.batchUpdate(updateBatch);
                            updateBatch.clear();
                        }

                        if (offset.getType() == Offset.Type.UPDATE && this.singleIndex != null) {
                            updateBatch.add(
                                    new ContentIndex.UpdateTask(
                                            offset.getResource(), offset.getOperations(), offset.getOffset()));
                            if (updateBatch.size() >= ContentIndex.UPDATE_SUB_BATCH_SIZE) {
                                lastAppliedOffset = this.singleIndex.batchUpdate(updateBatch);
                                updateBatch.clear();
                            }
                        } else {
                            this.applyOffset(offset);
                            lastAppliedOffset = offset.getOffset();
                        }
                    } catch (Exception e) {
                        log.error(
                                Constants.E_LOG_UPDATE_APPLY_OFFSET_FAILED,
                                offset.getOffset(),
                                offset.getType(),
                                offset.getResource(),
                                e.getMessage());
                        this.persistCheckpoint(
                                lastAppliedOffset,
                                fromOffset,
                                toOffset,
                                effectiveContext,
                                effectiveName,
                                effectiveType,
                                effectiveResource,
                                effectiveIsPublic,
                                effectivePendingSyncPhases);
                        throw e;
                    }
                }

                if (!updateBatch.isEmpty()) {
                    try {
                        lastAppliedOffset = this.singleIndex.batchUpdate(updateBatch);
                    } catch (Exception e) {
                        log.error("Batch update flush failed: {}", e.getMessage());
                        this.persistCheckpoint(
                                lastAppliedOffset,
                                fromOffset,
                                toOffset,
                                effectiveContext,
                                effectiveName,
                                effectiveType,
                                effectiveResource,
                                effectiveIsPublic,
                                effectivePendingSyncPhases);
                        throw e;
                    }
                }

                lastAppliedOffset = currentToOffset;
                currentFromOffset = currentToOffset;

                this.consumersIndex.setConsumer(
                        new LocalConsumer(
                                effectiveContext,
                                effectiveName,
                                effectiveType,
                                effectiveResource,
                                effectiveIsPublic,
                                LocalConsumer.Status.RUNNING,
                                lastAppliedOffset,
                                toOffset,
                                effectivePendingSyncPhases),
                        true);

                batchCount++;
                if (batchCount % FLUSH_EVERY_N_BATCHES == 0) {
                    for (ContentIndex idx : this.indices.values()) {
                        idx.flush();
                    }
                }
            }

            for (ContentIndex idx : this.indices.values()) {
                idx.flush();
            }

            log.info(Constants.I_LOG_UPDATE_CONSUMER_SUCCESS, this.consumerType, lastAppliedOffset);
            return true;
        } catch (Exception e) {
            log.error(Constants.E_LOG_UPDATE_FAILED, e.getMessage());
            throw new RuntimeException("Update failed for consumer [" + this.consumerType + "]", e);
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

        switch (offset.getType()) {
            case CREATE:
                if (offset.getPayload() != null) {
                    JsonNode payload = this.mapper.valueToTree(offset.getPayload());
                    String cveType = Cve.deriveType(id);
                    // Inject the CTI offset value into the payload, so it is persisted
                    if (payload.isObject()) {
                        ((ObjectNode) payload).put(Constants.KEY_OFFSET, offset.getOffset());
                    }
                    String type = null;

                    if (cveType != null) {
                        type = Constants.KEY_CVES;
                    } else if (payload.has(Constants.KEY_TYPE)) {
                        type = payload.get(Constants.KEY_TYPE).asText();
                        if (Constants.TYPE_IOC.equalsIgnoreCase(type)) {
                            type = Constants.KEY_IOCS;
                        }
                    }

                    if (Constants.KEY_CVES.equals(type) && payload.isObject() && cveType != null) {
                        ((ObjectNode) payload).put(Constants.KEY_TYPE, cveType);
                    }

                    if (type != null) {
                        index = this.indices.get(type);
                        if (index != null) {
                            CompletableFuture<Void> future = new CompletableFuture<>();
                            index.create(
                                    id,
                                    payload,
                                    ActionListener.wrap(r -> future.complete(null), future::completeExceptionally),
                                    WriteRequest.RefreshPolicy.NONE);
                            try {
                                future.get(PluginSettings.getInstance().getClientTimeout(), TimeUnit.SECONDS);
                            } catch (ExecutionException e) {
                                Throwable cause = e.getCause();
                                throw (cause instanceof Exception ex) ? ex : e;
                            }
                        } else {
                            log.warn(Constants.W_LOG_UPDATE_NO_INDEX_FOR_TYPE, type);
                        }
                    }
                }
                break;
            case UPDATE:
                index = this.findIndexForId(id);
                index.update(id, offset.getOperations(), offset.getOffset());
                break;
            case DELETE:
                if (this.shouldSkipDelete(id)) {
                    log.debug(Constants.D_LOG_UPDATE_SKIP_CVE_DELETE, id);
                    break;
                }
                index = this.findIndexForId(id);
                index.delete(id);
                break;
            default:
                log.warn(Constants.W_LOG_UPDATE_UNSUPPORTED_OPERATION, offset.getType());
                break;
        }
    }

    /**
     * CVE removals from CTI are intentionally ignored.
     *
     * <p>We skip delete operations when processing the CVE consumer or when the resource ID follows
     * the CVE identifier pattern.
     */
    private boolean shouldSkipDelete(String id) {
        if (Cve.deriveType(id) != null) {
            return true;
        }
        return this.cveCatalog;
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
        if (Constants.KEY_POLICY.equals(id)) {
            ContentIndex policyIndex = this.indices.get(Constants.KEY_POLICY);
            if (policyIndex != null) {
                return policyIndex;
            }
            throw new ResourceNotFoundException("Policy index not found.");
        }

        if (this.singleIndex != null) {
            return this.singleIndex;
        }

        for (ContentIndex index : this.indices.values()) {
            if (index.exists(id)) {
                return index;
            }
        }
        throw new ResourceNotFoundException(
                "Document with ID '" + id + "' could not be found in any ContentIndex.");
    }

    private void persistCheckpoint(
            long lastAppliedOffset,
            long fromOffset,
            long toOffset,
            String effectiveContext,
            String effectiveName,
            String effectiveType,
            String effectiveResource,
            boolean effectiveIsPublic,
            List<String> effectivePendingSyncPhases) {
        if (lastAppliedOffset > fromOffset) {
            try {
                this.consumersIndex.setConsumer(
                        new LocalConsumer(
                                effectiveContext,
                                effectiveName,
                                effectiveType,
                                effectiveResource,
                                effectiveIsPublic,
                                LocalConsumer.Status.RUNNING,
                                lastAppliedOffset,
                                toOffset,
                                effectivePendingSyncPhases),
                        true);
            } catch (Exception ce) {
                log.error(
                        "Failed to persist failure checkpoint at offset [{}]: {}",
                        lastAppliedOffset,
                        ce.getMessage());
            }
        }
    }

    private String firstNonBlank(String value, String fallback) {
        return value == null || value.isBlank() ? fallback : value;
    }
}
