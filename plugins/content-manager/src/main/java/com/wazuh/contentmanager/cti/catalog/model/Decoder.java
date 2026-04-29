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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Arrays;
import java.util.List;

import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.YamlUtils;

/** Model representing a Decoder resource. */
public class Decoder extends Resource {
    private static final Logger log = LogManager.getLogger(Decoder.class);

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

    @JsonProperty("yaml")
    private String yaml;

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
        if (payload.has(Constants.KEY_DOCUMENT)) {
            JsonNode docNode = payload.get(Constants.KEY_DOCUMENT);
            decoder.setYaml(YamlUtils.toYaml(docNode, DECODER_ORDER_KEYS));
        }

        return decoder;
    }

    /**
     * Sets the creation time on the given decoder JSON node, inside {@code metadata.date}.
     *
     * @param resourceNode The decoder JSON node.
     * @param timestamp The timestamp to set.
     */
    public static void setCreationTime(ObjectNode resourceNode, String timestamp) {
        ObjectNode metadataNode = Resource.getOrCreateMetadataNode(resourceNode);
        metadataNode.put(Constants.KEY_DATE, timestamp);
    }

    /**
     * Sets the last modification time on the given decoder JSON node, inside {@code
     * metadata.modified}.
     *
     * @param resourceNode The decoder JSON node.
     * @param timestamp The timestamp to set.
     */
    public static void setLastModificationTime(ObjectNode resourceNode, String timestamp) {
        ObjectNode metadataNode = Resource.getOrCreateMetadataNode(resourceNode);
        metadataNode.put(Constants.KEY_MODIFIED, timestamp);
    }

    /**
     * Gets the YAML string representation of this decoder.
     *
     * @return The decoder content in YAML format.
     */
    public String getYaml() {
        return this.yaml;
    }

    /**
     * Sets the YAML string representation of this decoder.
     *
     * @param yaml The decoder content in YAML format.
     */
    public void setYaml(String yaml) {
        this.yaml = yaml;
    }

    @Override
    public String toString() {
        return "Decoder{" + "yaml='" + this.yaml + '\'' + ", " + super.toString() + '}';
    }
}
