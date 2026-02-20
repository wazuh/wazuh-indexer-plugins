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

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.Arrays;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.utils.Constants;

/** Model representing a Decoder resource. */
public class Decoder extends Resource {
    private static final Logger log = LogManager.getLogger(Decoder.class);

    // Tools for YAML generation
    private static final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    private static final List<String> DECODER_ORDER_KEYS =
            Arrays.asList(
                    "name",
                    "metadata",
                    "parents",
                    "definitions",
                    "check",
                    "parse|event.original",
                    "parse|message",
                    "normalize");

    @JsonProperty("decoder")
    private String decoder;

    /** Default constructor. */
    public Decoder() {
        super();
    }

    /**
     * Factory method to create a Decoder instance from a raw JSON payload.
     *
     * @param payload The raw JSON object containing the decoder data.
     * @return A populated Decoder object with the generated YAML string.
     */
    public static Decoder fromPayload(JsonNode payload) {
        Decoder decoder = new Decoder();
        // 1. Basic logic for every resource
        Resource resource = new Resource();
        resource.populateResource(decoder, payload);

        // 2. Decoder-specific logic (YAML generation)
        if (payload.has("document")) {
            decoder.setDecoder(Decoder.toYamlString(payload));
        }

        return decoder;
    }

    /**
     * Generates a YAML representation for decoder documents.
     *
     * @param payload The source JSON object.
     * @return A string containing the formatted YAML, or {@code null} if the "document" key is
     *     missing or an error occurs.
     */
    private static String toYamlString(JsonNode payload) {
        try {
            if (!payload.has("document")) {
                return null;
            }
            JsonNode docNode = payload.get("document");

            if (docNode != null && docNode.isObject()) {
                Map<String, Object> orderedDecoderMap = new LinkedHashMap<>();

                // Add keys in order
                for (String key : DECODER_ORDER_KEYS) {
                    if (docNode.has(key)) orderedDecoderMap.put(key, docNode.get(key));
                }

                // Add remaining keys
                Iterator<Map.Entry<String, JsonNode>> fields = docNode.fields();
                while (fields.hasNext()) {
                    Map.Entry<String, JsonNode> field = fields.next();
                    if (!DECODER_ORDER_KEYS.contains(field.getKey())) {
                        orderedDecoderMap.put(field.getKey(), field.getValue());
                    }
                }
                return yamlMapper.writeValueAsString(orderedDecoderMap);
            }
        } catch (IOException e) {
            log.error("Failed to convert decoder payload to YAML: {}", e.getMessage(), e);
        }
        return null;
    }

    /**
     * Sets the creation time on the given decoder JSON node.
     *
     * @param resourceNode The decoder JSON node.
     * @param timestamp The timestamp to set.
     */
    public static void setCreationTime(ObjectNode resourceNode, String timestamp) {
        ObjectNode authorNode = Decoder.getOrCreateAuthorNode(resourceNode);
        authorNode.put(Constants.KEY_DATE, timestamp);
    }

    /**
     * Sets the last modification time on the given decoder JSON node.
     *
     * @param resourceNode The decoder JSON node.
     * @param timestamp The timestamp to set.
     */
    public static void setLastModificationTime(ObjectNode resourceNode, String timestamp) {
        ObjectNode authorNode = Decoder.getOrCreateAuthorNode(resourceNode);
        authorNode.put(Constants.KEY_MODIFIED, timestamp);
    }

    /**
     * Retrieves the author object node from the given resource node's metadata.
     * If the "metadata" node or its child "author" node do not exist, they are
     * created and appropriately attached to the resource node hierarchy.
     *
     * @param resourceNode The resource JSON node to extract or attach the author node to.
     * @return The existing or newly created author {@link ObjectNode}.
     */
    private static ObjectNode getOrCreateAuthorNode(ObjectNode resourceNode) {
        ObjectNode metadataNode;
        if (resourceNode.has(Constants.KEY_METADATA)
                && resourceNode.get(Constants.KEY_METADATA).isObject()) {
            metadataNode = (ObjectNode) resourceNode.get(Constants.KEY_METADATA);
        } else {
            metadataNode = MAPPER.createObjectNode();
            resourceNode.set(Constants.KEY_METADATA, metadataNode);
        }

        ObjectNode authorNode;
        if (metadataNode.has(Constants.KEY_AUTHOR)
                && metadataNode.get(Constants.KEY_AUTHOR).isObject()) {
            authorNode = (ObjectNode) metadataNode.get(Constants.KEY_AUTHOR);
        } else {
            authorNode = MAPPER.createObjectNode();
            metadataNode.set(Constants.KEY_AUTHOR, authorNode);
        }
        return authorNode;
    }

    /**
     * Gets the decoder YAML string.
     *
     * @return The decoder content in YAML format.
     */
    public String getDecoder() {
        return this.decoder;
    }

    /**
     * Sets the decoder YAML string.
     *
     * @param decoder The decoder content in YAML format.
     */
    public void setDecoder(String decoder) {
        this.decoder = decoder;
    }

    @Override
    public String toString() {
        return "Decoder{" + "decoder='" + this.decoder + '\'' + ", " + super.toString() + '}';
    }
}
