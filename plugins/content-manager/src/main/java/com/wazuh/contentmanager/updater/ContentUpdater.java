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
package com.wazuh.contentmanager.updater;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.model.ctiapi.ContextChanges;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.util.Privileged;
import com.wazuh.contentmanager.util.VisibleForTesting;

/** Class responsible for managing content updates by fetching and applying changes in chunks. */
public class ContentUpdater {
    private static final Integer CHUNK_MAX_SIZE = 1000;
    private static final Logger log = LogManager.getLogger(ContentUpdater.class);
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;
    public ContentUpdater INSTANCE;

    /** Exception thrown by the Content Updater in case of errors. */
    public static class ContentUpdateException extends RuntimeException {
        /**
         * Constructor method
         *
         * @param message Message to be thrown
         * @param cause Cause of the exception
         */
        public ContentUpdateException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Constructor method
     *
     * @param client the OpenSearch Client to interact with the cluster
     */
    public ContentUpdater(Client client) {
        this.contentIndex = new ContentIndex(client);
        this.contextIndex = new ContextIndex(client);
    }

    /**
     * Fetches and applies content updates in chunks from the current stored offset to the latest
     * available offset. It iterates over the updates and applies them in batch processing.
     *
     * @param from [PlaceHolderForTesting] Offset to start fetching updates from. TODO: Remove.
     * @param to [PlaceHolderForTesting] Offset to end fetching updates to. TODO: Remove.
     * @throws ContentUpdateException If there was an error fetching the changes.
     */
    public void fetchAndApplyUpdates(Long from, Long to) throws ContentUpdateException {
        // Placeholder for testing purposes. TODO: Remove.
        Long currentOffset;
        Long lastOffset;
        if (from != null) {
            currentOffset = from;
        } else {

            currentOffset = this.getCurrentOffset();
        }
        if (to != null) {
            lastOffset = to;
        } else {
            lastOffset = this.getLatestOffset();
        }
        log.info("Current offset: {}, Last offset: {}", currentOffset, lastOffset);

        if (lastOffset <= currentOffset) {
            log.info("No new updates available. Current offset ({}) is up to date.", currentOffset);
            return;
        }

        log.info("New offsets available updating to offset: {}", lastOffset);
        while (currentOffset < lastOffset) {
            Long nextOffset = Math.min(currentOffset + CHUNK_MAX_SIZE, lastOffset);
            ContextChanges changes =
                    this.getContextChanges(currentOffset.toString(), nextOffset.toString());
            log.info("Fetched offsets from {} to {}", currentOffset, nextOffset);

            // If there is an error fetching the changes, stop the process.
            if (changes == null) {
                throw new ContentUpdateException(
                        "Unable to fetch changes for offsets " + currentOffset + " to " + nextOffset, null);
            }
            // Apply the fetched changes to the indexed context.
            if (!this.patchContextIndex(changes)) {
                // If there was an error applying the changes, restart the consumer info.
                restartConsumerInfo();
                log.warn("Restarted consumer info. Current offset set to 0.");
                return;
            }

            currentOffset = nextOffset;
        }

        //        this.postUpdateCommand();
    }

    /**
     * Fetches the context changes between a given offset range from the CTI API.
     *
     * @param fromOffset Starting offset (inclusive).
     * @param toOffset Ending offset (exclusive).
     * @return ContextChanges object containing the changes.
     */
    @VisibleForTesting
    ContextChanges getContextChanges(String fromOffset, String toOffset) {
        return Privileged.doPrivilegedRequest(
                () -> CTIClient.getInstance().getChanges(fromOffset, toOffset, null));
    }

    /**
     * Retrieves the latest offset from the CTI API.
     *
     * @return Latest available offset.
     */
    @VisibleForTesting
    Long getLatestOffset() {
        ConsumerInfo consumerInfo =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());
        return consumerInfo.getLastOffset();
    }

    /**
     * Retrieves the current stored "last" offset from {@link ContextIndex}.
     *
     * @return The current "last" offset.
     */
    @VisibleForTesting
    Long getCurrentOffset() {
        return contextIndex
                .getConsumer(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID)
                .getLastOffset();
    }

    /**
     * Applies the fetched changes to the indexed context.
     *
     * @param changes Detected context changes.
     * @return true if the changes were successfully applied, false otherwise.
     */
    @VisibleForTesting
    boolean patchContextIndex(ContextChanges changes) {
        try {
            // Apply the changes to the context index.
            contentIndex.patch(changes);
        } catch (ExecutionException | InterruptedException | TimeoutException | IOException e) {
            log.error("Failed to apply changes to content index: {}", e.toString());
            return false;
        }

        return true;
    }

    /** Posts a new command to the Command Manager informing about the new changes. */
    @VisibleForTesting
    void postUpdateCommand() {
        // Post new command informing the new changes.
        Privileged.doPrivilegedRequest(
                () -> {
                    CommandManagerClient.getInstance()
                            .postCommand(Command.create(getCurrentOffset().toString()));
                    return null;
                });
    }

    /** Resets the consumer info by setting its last offset to zero. */
    @VisibleForTesting
    void restartConsumerInfo() {
        contextIndex.index(
                new ConsumerInfo(PluginSettings.CONSUMER_ID, PluginSettings.CONTEXT_ID, 0L, null));
    }
}
