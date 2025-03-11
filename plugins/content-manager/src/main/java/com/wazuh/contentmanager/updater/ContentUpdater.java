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
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.model.ctiapi.ContextConsumerCatalog;
import com.wazuh.contentmanager.model.ctiapi.Offset;
import com.wazuh.contentmanager.model.ctiapi.Offsets;
import com.wazuh.contentmanager.util.Privileged;
import com.wazuh.contentmanager.util.http.QueryParameters;

public class ContentUpdater {
    private static final Integer CHUNK_MAX_SIZE = 1000;
    private static final Logger log = LogManager.getLogger(ContentUpdater.class);

    /**
     * Fetches and applies content updates in chunks from the current stored offset to the latest
     * available offset. It iterates over the updates and applies them in batch processing.
     */
    public void fetchAndApplyUpdates() {
        try {
            Long currentOffset = this.getStoredOffset();
            Long lastOffset = this.getLatestOffset();
            List<Offset> allOffsets = new ArrayList<>();

            if (lastOffset <= currentOffset) {
                log.info("No new updates available. Current offset ({}) is up to date.", currentOffset);
                return;
            }

            log.info("Fetching content updates from offset {} to {}", currentOffset, lastOffset);

            while (currentOffset < lastOffset) {
                Long nextOffset = Math.min(currentOffset + CHUNK_MAX_SIZE, lastOffset);
                Offsets offsets;

                try {
                    offsets = this.getContextChanges(currentOffset, nextOffset);
                    log.info("Fetched offsets from {} to {}", currentOffset, nextOffset);
                } catch (IOException e) {
                    log.error("Error fetching changes for offsets {} to {}", currentOffset, nextOffset, e);
                    break; // Stop loop to prevent infinite retries in case of persistent API issues
                }

                // Merge new offsets into the accumulated list
                allOffsets.addAll(offsets.getOffsetList());

                // Update the offset for the next iteration
                Long maxFetchedOffset =
                        offsets.getOffsetList().stream()
                                .map(Offset::getOffset)
                                .max(Long::compareTo)
                                .orElse(currentOffset);

                // Ensure progress is made to prevent infinite loops
                if (maxFetchedOffset > currentOffset) {
                    currentOffset = maxFetchedOffset;
                } else {
                    log.warn(
                            "Fetched offsets did not provide a new highest value. Stopping to prevent infinite loop.");
                    break;
                }
            }
            this.patchContextWithNewOffset(new Offsets(allOffsets));
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
    private Offsets getContextChanges(Long fromOffset, Long toOffset) throws IOException {
        SimpleHttpResponse response =
                Privileged.doPrivilegedRequest(
                        () ->
                                CTIClient.getInstance()
                                        .getContextChanges(
                                                contextQueryParameters(fromOffset.toString(), toOffset.toString())));

        if (response == null || response.getBodyBytes() == null) {
            throw new IOException(
                    "Received null or empty response from API for offsets " + fromOffset + " to " + toOffset);
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
     * Retrieves the currently stored offset. This is a placeholder method and should be implemented
     * to fetch the actual stored value.
     *
     * @return The current stored offset.
     */
    private Long getStoredOffset() {
        return 1234L; // Placeholder for actual implementation
    }

    private void patchContextWithNewOffset(Offsets offsets) {
        return;
    }

    /**
     * Builds query parameters for the API request to fetch context changes.
     *
     * @param fromOffset Starting offset (inclusive).
     * @param toOffset Ending offset (exclusive).
     * @return A map of query parameters.
     */
    private Map<String, String> contextQueryParameters(String fromOffset, String toOffset) {
        Map<String, String> params = new HashMap<>();
        params.put(QueryParameters.FROM_OFFSET, fromOffset);
        params.put(QueryParameters.TO_OFFSET, toOffset);
        params.put(QueryParameters.WITH_EMPTIES, "");
        return params;
    }
}
