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

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.model.ctiapi.ContentChanges;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.util.Privileged;
import com.wazuh.contentmanager.util.VisibleForTesting;

/** Class responsible for managing content updates by fetching and applying changes in chunks. */
public class ContentUpdater {
    private static final int CHUNK_MAX_SIZE = 1000;
    private static final Logger log = LogManager.getLogger(ContentUpdater.class);
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;
    private final CTIClient ctiClient;

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
     * Constructor. Mainly used for testing purposes.
     *
     * @param client the OpenSearch Client to interact with the cluster
     * @param ctiClient the CTIClient to interact with the CTI API
     */
    public ContentUpdater(Client client, CTIClient ctiClient) {
        this.contentIndex = new ContentIndex(client);
        this.contextIndex = new ContextIndex(client);
        this.ctiClient = ctiClient;
    }

    /**
     * Default constructor. TODO unused method.
     *
     * @param client the OpenSearch Client to interact with the cluster
     */
    public ContentUpdater(Client client) {
        this(client, CTIClient.getInstance());
    }

    /**
     * Fetches and applies content updates in chunks from the current stored offset to the latest
     * available offset. It iterates over the updates and applies them in batch processing.
     *
     * @return true if the updates were successfully applied, false otherwise.
     * @throws ContentUpdateException If there was an error fetching the changes.
     */
    public boolean update() throws ContentUpdateException {
        long currentOffset = this.getCurrentOffset();
        long lastOffset = this.getLatestOffset();

        if (lastOffset == currentOffset) {
            log.info("No updates available. Current offset ({}) is up to date.", currentOffset);
            return true;
        }

        log.info("New updates available from offset {} to {}", currentOffset, lastOffset);
        while (currentOffset < lastOffset) {
            long nextOffset = Math.min(currentOffset + ContentUpdater.CHUNK_MAX_SIZE, lastOffset);
            ContentChanges changes = this.getChanges(currentOffset, nextOffset);
            log.debug("Fetched offsets from {} to {}", currentOffset, nextOffset);

            if (changes == null) {
                log.error("Unable to fetch changes for offsets {} to {}", currentOffset, nextOffset);
                this.updateContext(0L);
                return false;
            }

            if (!this.applyChanges(changes)) {
                this.updateContext(0L);
                return false;
            }

            currentOffset = nextOffset;
            log.debug("Update current offset to {}", currentOffset);
        }

        this.updateContext(currentOffset);
        this.postUpdateCommand();
        return true;
    }

    /**
     * Fetches the context changes between a given offset range from the CTI API. TODO check if we can
     * remove this wrapper method.
     *
     * @param fromOffset Starting offset (inclusive).
     * @param toOffset Ending offset (exclusive).
     * @return ContextChanges object containing the changes.
     */
    @VisibleForTesting
    public ContentChanges getChanges(long fromOffset, long toOffset) {
        return Privileged.doPrivilegedRequest(
                () -> this.ctiClient.getChanges(fromOffset, toOffset, false));
    }

    /**
     * Retrieves the latest offset from the CTI API. TODO the last offset should be read from the
     * wazuh-context index, not from the CTI API. ContextIndex.getLastOffset()
     *
     * @return Latest available offset.
     */
    @VisibleForTesting
    long getLatestOffset() {
        ConsumerInfo consumerInfo = Privileged.doPrivilegedRequest(this.ctiClient::getCatalog);
        return consumerInfo.getLastOffset();
    }

    /**
     * Retrieves the current stored "last" offset from {@link ContextIndex}. TODO this should be
     * responsibility of the ContextIndex class. For example: ContextIndex.getOffset().
     *
     * @return The current "last" offset.
     */
    @VisibleForTesting
    long getCurrentOffset() {
        ConsumerInfo consumer =
                this.contextIndex.getConsumer(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID);
        return consumer != null ? consumer.getLastOffset() : 0L;
    }

    /**
     * Applies the fetched changes to the indexed content. TODO check if we can remove this wrapper
     * method.
     *
     * @param changes Detected content changes.
     * @return true if the changes were successfully applied, false otherwise.
     */
    @VisibleForTesting
    boolean applyChanges(ContentChanges changes) {
        try {
            this.contentIndex.patch(changes);
            return true;
        } catch (RuntimeException e) {
            log.error("Failed to apply changes to content index", e);
            return false;
        }
    }

    /**
     * Posts a new command to the Command Manager informing about the new changes. TODO check if we
     * can remove this wrapper method.
     */
    @VisibleForTesting
    void postUpdateCommand() {
        Privileged.doPrivilegedRequest(
                () -> {
                    CommandManagerClient.getInstance()
                            .postCommand(Command.create(String.valueOf(this.getCurrentOffset())));
                    return null;
                });
    }

    /**
     * Resets the consumer info by setting its last offset to zero. TODO this should be responsibility
     * of the ContextIndex class. For example: ContextIndex.setOffset(offset).
     */
    @VisibleForTesting
    void updateContext(Long newOffset) {
        this.contextIndex.index(
                new ConsumerInfo(PluginSettings.CONSUMER_ID, PluginSettings.CONTEXT_ID, newOffset, null));
        log.info("Updated context index with new offset {}", newOffset);
    }
}
