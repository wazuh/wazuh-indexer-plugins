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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.utils.HashCalculator;
import com.wazuh.contentmanager.utils.Constants;

/** Base model representing a generic catalog resource within the CTI context. */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class Resource {
    private static final Logger log = LogManager.getLogger(Resource.class);
    protected static final ObjectMapper MAPPER = new ObjectMapper();

    // JSON Key Constants
    private static final String JSON_DOCUMENT_KEY = "document";
    private static final String JSON_METADATA_KEY = "metadata";
    private static final String JSON_CUSTOM_FIELDS_KEY = "custom_fields";
    private static final String JSON_DATASET_KEY = "dataset";
    private static final String JSON_RELATED_KEY = "related";
    private static final String JSON_SIGMA_ID_KEY = "sigma_id";

    @JsonProperty("document")
    private Map<String, Object> document;

    @JsonProperty("hash")
    private Map<String, String> hash;

    @JsonProperty("space")
    private Map<String, Object> space;

    /** Default constructor. */
    public Resource() {}

    /**
     * Factory method to create a Resource instance from a raw JsonNode payload.
     *
     * @param payload The raw JSON object containing the resource data.
     * @return A fully populated Resource instance.
     */
    public static Resource fromPayload(JsonNode payload) {
        Resource resource = new Resource();
        resource.populateResource(resource, payload);
        return resource;
    }

    /**
     * Populates the common fields of a Resource instance.
     *
     * @param resource The resource instance to populate.
     * @param payload The source JSON payload.
     */
    protected void populateResource(Resource resource, JsonNode payload) {
        // 1. Process Document
        if (payload.has(JSON_DOCUMENT_KEY) && payload.get(JSON_DOCUMENT_KEY).isObject()) {
            ObjectNode rawDoc = (ObjectNode) payload.get(JSON_DOCUMENT_KEY).deepCopy();
            Resource.preprocessDocument(rawDoc);

            resource.setDocument(MAPPER.convertValue(rawDoc, Map.class));

            // 2. Calculate Hash
            String hashStr = HashCalculator.sha256(rawDoc.toString());
            if (!hashStr.isEmpty()) {
                Map<String, String> hashMap = new HashMap<>();
                hashMap.put("sha256", hashStr);
                resource.setHash(hashMap);
            }
        }
        String type =
                payload.has(Constants.KEY_TYPE) ? payload.get(Constants.KEY_TYPE).getAsString() : "none";
        if (!type.equals(Constants.TYPE_IOC)) {
            // 3. Set Space if not present in resource payload
            this.populateSpaceObject(resource, payload);
        }
    }

    private void populateSpaceObject(Resource resource, JsonObject payload) {
        Map<String, Object> spaceMap = new HashMap<>();
        String spaceName = Space.STANDARD.toString();
        if (payload.has("space") && payload.get("space").isObject()) {
            JsonNode spaceObj = payload.get("space");
            if (spaceObj.has("name")) {
                spaceName = spaceObj.get("name").asText();
            }
            if (spaceObj.has("hash") && spaceObj.get("hash").isObject()) {
                Map<String, String> hashMap = MAPPER.convertValue(spaceObj.get("hash"), Map.class);
                spaceMap.put("hash", hashMap);
            }
        }
        spaceMap.put("name", spaceName);
        resource.setSpace(spaceMap);
    }

    /**
     * Sanitizes the document by removing internal or unnecessary fields.
     *
     * @param document The JSON object representing the document content.
     */
    protected static void preprocessDocument(ObjectNode document) {
        if (document.has(JSON_METADATA_KEY) && document.get(JSON_METADATA_KEY).isObject()) {
            ObjectNode metadata = (ObjectNode) document.get(JSON_METADATA_KEY);
            metadata.remove(JSON_CUSTOM_FIELDS_KEY);
            metadata.remove(JSON_DATASET_KEY);
        }

        if (document.has(JSON_RELATED_KEY)) {
            JsonNode relatedElement = document.get(JSON_RELATED_KEY);
            if (relatedElement.isObject()) {
                Resource.sanitizeRelatedObject((ObjectNode) relatedElement);
            } else if (relatedElement.isArray()) {
                ArrayNode relatedArray = (ArrayNode) relatedElement;
                for (JsonNode element : relatedArray) {
                    if (element.isObject()) {
                        Resource.sanitizeRelatedObject((ObjectNode) element);
                    }
                }
            }
        }
    }

    /**
     * Helper method to sanitize a single "related" object.
     *
     * @param relatedObj The JSON object inside the "related" field.
     */
    private static void sanitizeRelatedObject(ObjectNode relatedObj) {
        if (relatedObj.has(JSON_SIGMA_ID_KEY)) {
            relatedObj.set(Constants.KEY_ID, relatedObj.get(JSON_SIGMA_ID_KEY));
            relatedObj.remove(JSON_SIGMA_ID_KEY);
        }
    }

    /**
     * Gets the document content.
     *
     * @return A Map representing the document.
     */
    public Map<String, Object> getDocument() {
        return this.document;
    }

    /**
     * Sets the document content.
     *
     * @param document A Map representing the document.
     */
    public void setDocument(Map<String, Object> document) {
        this.document = document;
    }

    /**
     * Gets the hash map containing checksums.
     *
     * @return A Map containing hash algorithms and values.
     */
    public Map<String, String> getHash() {
        return this.hash;
    }

    /**
     * Sets the hash map.
     *
     * @param hash A Map containing hash algorithms and values.
     */
    public void setHash(Map<String, String> hash) {
        this.hash = hash;
    }

    /**
     * Gets the space definition.
     *
     * @return A Map containing space details.
     */
    public Map<String, Object> getSpace() {
        return this.space;
    }

    /**
     * Sets the space definition.
     *
     * @param space A Map containing space details.
     */
    public void setSpace(Map<String, Object> space) {
        this.space = space;
    }

    @Override
    public String toString() {
        return "Resource{"
                + "document="
                + this.document
                + ", hash="
                + this.hash
                + ", space="
                + this.space
                + '}';
    }
}
