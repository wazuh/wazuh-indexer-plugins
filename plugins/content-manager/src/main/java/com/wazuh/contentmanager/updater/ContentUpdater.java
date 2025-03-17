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

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.xcontent.*;

import java.io.IOException;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ContextConsumerCatalog;
import com.wazuh.contentmanager.model.ctiapi.Offsets;
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
     */
    public void fetchAndApplyUpdates() throws ContentUpdateException {
        // Offset model will be renamed to ContextChange
        Long currentOffset = this.getCurrentOffset();
        Long lastOffset = this.getLatestOffset();

        if (lastOffset <= currentOffset) {
            log.info("No new updates available. Current offset ({}) is up to date.", currentOffset);
            return;
        }

        log.info("New offsets available updating to offset: {}", lastOffset);
        while (currentOffset < lastOffset) {
            Long nextOffset = Math.min(currentOffset + CHUNK_MAX_SIZE, lastOffset);
            Offsets changes = this.getContextChanges(currentOffset.toString(), nextOffset.toString());
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
     * @return Offsets object containing the changes.
     */
    public Offsets getContextChanges(String fromOffset, String toOffset) {
        try {
            SimpleHttpResponse response =
                    Privileged.doPrivilegedRequest(
                            () -> CTIClient.getInstance().getContextChanges(fromOffset, toOffset, null));

            if (response == null || response.getBodyBytes() == null) {
                throw new IOException("Empty response for offsets " + fromOffset + " to " + toOffset);
            }

            XContent xContent = XContentType.JSON.xContent();
            return Offsets.parse(
                    xContent.createParser(
                            NamedXContentRegistry.EMPTY,
                            DeprecationHandler.IGNORE_DEPRECATIONS,
                            response.getBodyBytes()));
        } catch (IOException e) {
            log.error("Error fetching changes for offsets {} to {}", fromOffset, toOffset, e);
            return null;
        }
    }

    /**
     * Retrieves the latest offset from the CTI API.
     *
     * @return Latest available offset.
     */
    public Long getLatestOffset() {
        try {
            SimpleHttpResponse response =
                    Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());

            if (response == null || response.getBodyBytes() == null) {
                throw new ContentUpdateException(
                        "Failed to fetch latest offset: API response is null", null);
            }

            XContent xContent = XContentType.JSON.xContent();
            return ContextConsumerCatalog.parse(
                            xContent.createParser(
                                    NamedXContentRegistry.EMPTY,
                                    DeprecationHandler.IGNORE_DEPRECATIONS,
                                    response.getBodyBytes()))
                    .getLastOffset();
        } catch (IOException e) {
            throw new ContentUpdateException("Error fetching latest offset", e);
        }
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
    public void patchContextIndex(Offsets changes) {
        // Placeholder for actual implementation.
        // ContentIndex.patch(changes);
    }

    /**
     * Posts a new command to the Command Manager informing the new changes.
     *
     * @param updatedOffset Last updated offset.
     */
    public void postUpdateCommand(Long updatedOffset) {
        try {
            // Post new command informing the new changes.
            CommandManagerClient.getInstance().postCommand(Command.generateCtiCommand());
        } catch (IOException e) {
            log.error("Error posting update command", e);
        }
    }
}
