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
import org.opensearch.core.xcontent.*;

import java.io.IOException;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.model.ctiapi.ContextChanges;
import com.wazuh.contentmanager.util.Privileged;

public class ContentUpdater {
    private static final Integer CHUNK_MAX_SIZE = 1000;
    private static final Logger log = LogManager.getLogger(ContentUpdater.class);

    public static class ContentUpdateException extends RuntimeException {
        public ContentUpdateException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Fetches and applies content updates in chunks from the current stored offset to the latest
     * available offset. It iterates over the updates and applies them in batch processing.
     *
     * @param fixedOffset [PlaceHolderForTesting] Offset to start fetching updates from. TODO: Remove.
     * @throws ContentUpdateException If there was an error fetching the changes.
     */
    public void fetchAndApplyUpdates(Long fixedOffset) throws ContentUpdateException {
        // Offset model will be renamed to ContextChange
        Long currentOffset = this.getCurrentOffset();
        Long lastOffset = this.getLatestOffset();

        // Placeholder for testing purposes. TODO: Remove.
        if (fixedOffset != null) {
            currentOffset = fixedOffset;
        }

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
            // If there was an error fetching the changes, stop the process.
            if (changes == null) {
                throw new ContentUpdateException(
                        "Error fetching changes for offsets " + currentOffset + " to " + nextOffset, null);
            }
            // Apply the fetched changes to the indexed context.
            this.patchContextIndex(changes);
            // Update the current offset.
            if (nextOffset >= currentOffset) {
                currentOffset = nextOffset;
            } else {
                log.info("No new updates available. Current offset ({}) is up to date.", currentOffset);
                break;
            }
        }
        // Post new command informing the new changes.
        this.postUpdateCommand(currentOffset);
    }

    /**
     * Fetches the context changes between a given offset range from the CTI API.
     *
     * @param fromOffset Starting offset (inclusive).
     * @param toOffset Ending offset (exclusive).
     * @return ContextChanges object containing the changes.
     */
    public ContextChanges getContextChanges(String fromOffset, String toOffset) {
        return Privileged.doPrivilegedRequest(
                () -> CTIClient.getInstance().getChanges(fromOffset, toOffset, null));
    }

    /**
     * Retrieves the latest offset from the CTI API.
     *
     * @return Latest available offset.
     */
    public Long getLatestOffset() {
        ConsumerInfo consumerInfo =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());
        return consumerInfo.getLastOffset();
    }

    /**
     * Retrieves the current stored offset from the wazuh-context index.
     *
     * @return The current offset.
     */
    public Long getCurrentOffset() {
        // Placeholder for actual implementation.
        // It should fetch the current offset from the index.
        // ContextIndex.get().getOffset();
        return 1234L;
    }

    /**
     * Apply the fetched changes to the indexed context.
     *
     * @param changes Detected Context changes.
     */
    public void patchContextIndex(ContextChanges changes) {
        // Placeholder for actual implementation.
        // ContentIndex.patch(changes);
    }

    /**
     * Posts a new command to the Command Manager informing the new changes.
     *
     * @param updatedOffset Last updated offset.
     */
    public void postUpdateCommand(Long updatedOffset) {
        // Post new command informing the new changes.
        Privileged.doPrivilegedRequest(
                () -> {
                    try {
                        CommandManagerClient.getInstance().postCommand(Command.generateCtiCommand());
                    } catch (IOException e) {
                        log.error("Error posting update command", e);
                    }
                    return null;
                });
    }
}
