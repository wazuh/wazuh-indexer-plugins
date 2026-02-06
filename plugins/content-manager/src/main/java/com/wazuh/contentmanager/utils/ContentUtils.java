/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.utils;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.time.Instant;

/** Common utility methods for Content Manager REST actions. */
public class ContentUtils {

    private static final ObjectMapper mapper = new ObjectMapper();

    private ContentUtils() {}

    /**
     * Adds or updates timestamp metadata (date, modified) and author structure in the resource node.
     *
     * @param resourceNode The resource object to update.
     * @param isCreate If true, sets creation 'date'. Always sets 'modified'.
     */
    public static void updateTimestampMetadata(ObjectNode resourceNode, boolean isCreate) {
        String currentTimestamp = Instant.now().toString();

        // Ensure metadata node exists
        ObjectNode metadataNode;
        if (resourceNode.has(Constants.KEY_METADATA)
                && resourceNode.get(Constants.KEY_METADATA).isObject()) {
            metadataNode = (ObjectNode) resourceNode.get(Constants.KEY_METADATA);
        } else {
            metadataNode = mapper.createObjectNode();
            resourceNode.set(Constants.KEY_METADATA, metadataNode);
        }

        // Ensure author node exists
        ObjectNode authorNode;
        if (metadataNode.has(Constants.KEY_AUTHOR)
                && metadataNode.get(Constants.KEY_AUTHOR).isObject()) {
            authorNode = (ObjectNode) metadataNode.get(Constants.KEY_AUTHOR);
        } else {
            authorNode = mapper.createObjectNode();
            metadataNode.set(Constants.KEY_AUTHOR, authorNode);
        }

        // Set timestamps
        if (isCreate) {
            authorNode.put(Constants.KEY_DATE, currentTimestamp);
        }
        authorNode.put(Constants.KEY_MODIFIED, currentTimestamp);
    }
}
