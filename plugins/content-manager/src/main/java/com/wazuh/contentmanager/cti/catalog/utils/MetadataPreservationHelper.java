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
package com.wazuh.contentmanager.cti.catalog.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.io.IOException;
import java.time.Instant;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;

/**
 * Utility class for preserving metadata during PUT operations.
 *
 * <p>This class provides a common method to preserve the {@code metadata.author.date} field from
 * existing documents while allowing other metadata fields to be updated. The {@code
 * metadata.author.modified} timestamp is always updated to the current time.
 */
public final class MetadataPreservationHelper {

    private static final String FIELD_DOCUMENT = "document";
    private static final String FIELD_METADATA = "metadata";
    private static final String FIELD_AUTHOR = "author";
    private static final String FIELD_DATE = "date";
    private static final String FIELD_MODIFIED = "modified";

    private MetadataPreservationHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Preserves only the date field from existing metadata and allows other metadata fields to be
     * updated.
     *
     * <p>The {@code metadata.author.date} is preserved from the existing document and cannot be
     * modified. All other metadata fields ({@code title}, {@code description}, {@code author.name})
     * can be updated from the request. The {@code metadata.author.modified} timestamp is always
     * updated to the current time.
     *
     * @param mapper the ObjectMapper instance for JSON operations
     * @param contentIndex the ContentIndex instance to retrieve the existing document
     * @param documentId the document ID to retrieve from the index
     * @param resourceNode the resource node to update with preserved metadata
     * @throws IOException if an error occurs retrieving the existing document
     */
    public static void preserveMetadataAndUpdateTimestamp(
            ObjectMapper mapper, ContentIndex contentIndex, String documentId, ObjectNode resourceNode)
            throws IOException {
        JsonNode existingDocument = contentIndex.getDocument(documentId);
        if (existingDocument == null) {
            throw new IOException("Document [" + documentId + "] not found.");
        }

        JsonNode existingMetadata = null;
        String preservedDate = null;
        if (existingDocument.has(FIELD_DOCUMENT) && existingDocument.get(FIELD_DOCUMENT).isObject()) {
            JsonNode existingDoc = existingDocument.get(FIELD_DOCUMENT);
            if (existingDoc.has(FIELD_METADATA) && existingDoc.get(FIELD_METADATA).isObject()) {
                existingMetadata = existingDoc.get(FIELD_METADATA);
                if (existingMetadata.has(FIELD_AUTHOR) && existingMetadata.get(FIELD_AUTHOR).isObject()) {
                    JsonNode existingAuthor = existingMetadata.get(FIELD_AUTHOR);
                    if (existingAuthor.has(FIELD_DATE)) {
                        preservedDate = existingAuthor.get(FIELD_DATE).asText();
                    }
                }
            }
        }

        ObjectNode requestMetadata = null;
        if (resourceNode.has(FIELD_METADATA) && resourceNode.get(FIELD_METADATA).isObject()) {
            requestMetadata = (ObjectNode) resourceNode.get(FIELD_METADATA);
        }

        ObjectNode finalMetadata;
        if (requestMetadata != null) {
            finalMetadata =
                    (ObjectNode) mapper.readTree(mapper.writeValueAsString(requestMetadata));
        } else if (existingMetadata != null) {
            finalMetadata = (ObjectNode) mapper.readTree(mapper.writeValueAsString(existingMetadata));
        } else {
            finalMetadata = mapper.createObjectNode();
        }

        ObjectNode authorNode;
        if (finalMetadata.has(FIELD_AUTHOR) && finalMetadata.get(FIELD_AUTHOR).isObject()) {
            authorNode = (ObjectNode) finalMetadata.get(FIELD_AUTHOR);
        } else {
            authorNode = mapper.createObjectNode();
            finalMetadata.set(FIELD_AUTHOR, authorNode);
        }

        if (preservedDate != null) {
            authorNode.put(FIELD_DATE, preservedDate);
        }

        authorNode.put(FIELD_MODIFIED, Instant.now().toString());
        resourceNode.set(FIELD_METADATA, finalMetadata);
    }
}

