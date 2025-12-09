package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.*;

/**
 * Model representing a Decoder resource.
 */
public class Decoder extends Resource {
    private static final Logger log = LogManager.getLogger(Decoder.class);

    // Tools for YAML generation
    private static final ObjectMapper jsonMapper = new ObjectMapper();
    private static final ObjectMapper yamlMapper = new ObjectMapper(new YAMLFactory());

    private static final List<String> DECODER_ORDER_KEYS = Arrays.asList(
        "name", "metadata", "parents", "definitions", "check",
        "parse|event.original", "parse|message", "normalize"
    );

    @JsonProperty("decoder")
    private String decoder;

    /**
     * Default constructor.
     */
    public Decoder() {
        super();
    }

    /**
     * Factory method to create a {@link Decoder} instance from a raw JSON payload.
     *
     * @param payload The raw JSON object containing the decoder data.
     * @return A populated {@link Decoder} object with the generated YAML string.
     */
    public static Decoder fromPayload(JsonObject payload) {
        Decoder decoder = new Decoder();
        // 1. Basic logic for every resource
        Resource.populateResource(decoder, payload);

        // 2. Decoder-specific logic (YAML generation)
        if (payload.has("document")) {
            decoder.setDecoder(toYamlString(payload));
        }

        return decoder;
    }

    /**
     * Generates a YAML representation for decoder documents.
     *
     * @param payload The source JSON object.
     * @return A string containing the formatted YAML, or {@code null} if the "document" key is missing or an error occurs.
     */
    private static String toYamlString(JsonObject payload) {
        try {
            if (!payload.has("document")) return null;
            JsonNode docNode = jsonMapper.readTree(payload.get("document").toString());

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
     * Gets the decoder YAML string.
     *
     * @return The decoder content in YAML format.
     */
    public String getDecoder() {
        return decoder;
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
        return "Decoder{" +
            "decoder='" + decoder + '\'' +
            ", " + super.toString() +
            '}';
    }
}
