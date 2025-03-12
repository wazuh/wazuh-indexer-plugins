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
import java.util.ArrayList;
import java.util.List;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ContextConsumerCatalog;
import com.wazuh.contentmanager.model.ctiapi.Offset;
import com.wazuh.contentmanager.model.ctiapi.Offsets;
import com.wazuh.contentmanager.util.Privileged;

public class ContentUpdater {
    private static final Integer CHUNK_MAX_SIZE = 1000;
    private static final Logger log = LogManager.getLogger(ContentUpdater.class);

    /**
     * Fetches and applies content updates in chunks from the current stored offset to the latest
     * available offset. It iterates over the updates and applies them in batch processing.
     */
    public void fetchAndApplyUpdates() {
        // Offset model will be renamed to ContextChange
        try {
            Long currentOffset = this.getCurrentOffset();
            Long lastOffset = this.getLatestOffset();
            List<Offset> changesToApply = new ArrayList<>();

            if (lastOffset <= currentOffset) {
                log.info("No new updates available. Current offset ({}) is up to date.", currentOffset);
                return;
            }

            log.info("Fetching content updates from offset {} to {}", currentOffset, lastOffset);

            while (currentOffset < lastOffset) {
                Long nextOffset = Math.min(currentOffset + CHUNK_MAX_SIZE, lastOffset);
                Offsets changes;

                try {
                    changes = this.getContextChanges(currentOffset.toString(), nextOffset.toString());
                    log.info("Fetched offsets from {} to {}", currentOffset, nextOffset);
                } catch (IOException e) {
                    log.error("Error fetching changes for offsets {} to {}", currentOffset, nextOffset, e);
                    break; // Stop loop to prevent infinite retries in case of persistent API issues
                }

                // Merge new offsets into the accumulated list
                changesToApply.addAll(changes.getOffsetList());

                // Update the offset for the next iteration
                Long maxFetchedOffset =
                        changes.getOffsetList().stream()
                                .map(Offset::getOffset)
                                .max(Long::compareTo)
                                .orElse(currentOffset);

                // Ensure progress is made to prevent infinite loops
                if (maxFetchedOffset > currentOffset) {
                    currentOffset = maxFetchedOffset;
                } else {
                    log.warn("Fetched offsets did not provide a new highest value.");
                    break;
                }
            }
            // Creates an Offsets (ContextChanges) instance that is passed to the patcher.
            this.applyChangesToContext(new Offsets(changesToApply));
            // Post new command informing the new changes.
            CommandManagerClient.getInstance().postCommand(Command.generateCtiCommand());
        } catch (IOException e) {
            log.error("Unexpected error while fetching content updates", e);
        }
    }

    /**
     * Fetches the context changes between a given offset range from the CTI API.
     *
     * @param fromOffset Starting offset (inclusive).
     * @param toOffset Ending offset (exclusive).
     * @return Offsets object containing the changes.
     * @throws IOException If the API response is null or fails to parse.
     */
    private Offsets getContextChanges(String fromOffset, String toOffset) throws IOException {
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
    }

    /**
     * Retrieves the latest offset from the CTI API.
     *
     * @return The latest available offset.
     * @throws IOException If the API response is null or fails to parse.
     */
    private Long getLatestOffset() throws IOException {
        SimpleHttpResponse response =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());

        if (response == null || response.getBodyBytes() == null) {
            throw new IOException("Failed to fetch latest offset: API response is null");
        }

        XContent xContent = XContentType.JSON.xContent();
        return ContextConsumerCatalog.parse(
                        xContent.createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.IGNORE_DEPRECATIONS,
                                response.getBodyBytes()))
                .getLastOffset();
    }

    /**
     * Retrieves the current stored offset from the wazuh-context index.
     *
     * @return The current offset.
     */
    private Long getCurrentOffset() {
        // Placeholder for actual implementation.
        // It should fetch the current offset from the index.
        // ContextIndex.get().getOffset();
        return 1234L;
    }

    /** Apply the fetched changes to the indexed context. */
    private void applyChangesToContext(Offsets changes) {
        // Placeholder for actual implementation.
        // ContentIndex.patch(changes);
        return;
    }
}
