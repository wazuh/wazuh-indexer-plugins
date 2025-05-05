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

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.model.ctiapi.ContentChanges;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.VisibleForTesting;

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
     * @param ctiClient the CTIClient to interact with the CTI API
     * @param contextIndex An object that handles context and consumer information
     * @param contentIndex An object that handles content index interactions
     */
    public ContentUpdater(CTIClient ctiClient, ContextIndex contextIndex, ContentIndex contentIndex) {
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
        this.ctiClient = ctiClient;
    }

    /**
     * Starts and orchestrates the process to update the content in the index with the latest changes
     * from the CTI API. The content needs an update when the "offset" and the "lastOffset" values are
     * different. In that case, the update process tries to bring the content up to date by querying
     * the CTI API for a list of changes to apply to the content. These changes are applied
     * sequentially. A maximum of {@link ContentUpdater#CHUNK_MAX_SIZE} changes are applied on each
     * iteration. When the update is completed, the value of "offset" is updated and equal to
     * "lastOffset" {@link ContextIndex#index(ConsumerInfo)}, and a command is generated for the
     * Command Manager {@link ContentUpdater#postUpdateCommand()}. If the update fails, the "offset"
     * is set to 0 to force a recovery from a snapshot.
     *
     * @return true if the updates were successfully applied, false otherwise.
     * @throws ContentUpdateException If there was an error fetching the changes.
     */
    public boolean update() throws ContentUpdateException {
        ConsumerInfo consumerInfo =
                this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID);
        long currentOffset = consumerInfo.getOffset();
        long lastOffset = consumerInfo.getLastOffset();

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
                consumerInfo.setOffset(0);
                consumerInfo.setLastOffset(0);
                return false;
            }

            if (!this.applyChanges(changes)) {
                consumerInfo.setOffset(0);
                consumerInfo.setLastOffset(0);
                return false;
            }

            currentOffset = nextOffset;
            log.debug("Update current offset to {}", currentOffset);
        }

        // Update consumer info.
        this.contextIndex.index(consumerInfo);
        this.postUpdateCommand();
        return true;
    }

    /**
     * Fetches the context changes between a given offset range from the CTI API.
     *
     * @param fromOffset Starting offset (inclusive).
     * @param toOffset Ending offset (exclusive).
     * @return ContextChanges object containing the changes.
     */
    @VisibleForTesting
    protected ContentChanges getChanges(long fromOffset, long toOffset) {
        return Privileged.doPrivilegedRequest(
                () -> this.ctiClient.getChanges(fromOffset, toOffset, false));
    }

    /**
     * Applies the fetched changes to the indexed content.
     *
     * @param changes Detected content changes.
     * @return true if the changes were successfully applied, false otherwise.
     */
    @VisibleForTesting
    protected boolean applyChanges(ContentChanges changes) {
        try {
            this.contentIndex.patch(changes);
            return true;
        } catch (RuntimeException e) {
            log.error("Failed to apply changes to content index", e);
            return false;
        }
    }

    /**
     * Posts a new command to the Command Manager informing about the new changes. TODO duplicated of
     * {@code SnapshotHelper#postUpdateCommand()}
     */
    @VisibleForTesting
    protected void postUpdateCommand() {
        ConsumerInfo consumerInfo =
                this.contextIndex.get(PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID);
        Privileged.doPrivilegedRequest(
                () -> {
                    CommandManagerClient.getInstance()
                            .postCommand(Command.create(String.valueOf(consumerInfo.getOffset())));
                    return null;
                });
    }
}
