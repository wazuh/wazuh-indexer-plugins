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
package com.wazuh.contentmanager.utils;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.DecimalNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.math.BigDecimal;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Shared utility for YAML - JSON conversions.
 *
 * <p>Uses Jackson's {@code YAMLFactory}-backed {@link ObjectMapper} configured with {@link
 * DeserializationFeature#USE_BIG_DECIMAL_FOR_FLOATS} to preserve type fidelity (e.g. {@code 5.0}
 * stays {@code 5.0} instead of being coerced to integer {@code 5}).
 */
public final class YamlUtils {

    private static final Logger log = LogManager.getLogger(YamlUtils.class);

    private static final ObjectMapper YAML_MAPPER;

    static {
        YAML_MAPPER = new ObjectMapper(new YAMLFactory());
        YAML_MAPPER.enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);
    }

    /**
     * Serializes a {@link JsonNode} document to a YAML string.
     *
     * @param document The document to serialize.
     * @return The YAML string, or {@code null}
     */
    public static String toYaml(JsonNode document) {
        if (document == null) {
            return null;
        }
        try {
            return YAML_MAPPER.writeValueAsString(document);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize document to YAML: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Serializes a {@link JsonNode} document to a YAML string with explicit key ordering.
     *
     * <p>Keys listed in {@code keyOrder} appear first (in the given order); any remaining keys follow
     * in their original iteration order.
     *
     * @param document The document to serialize. May be {@code null}.
     * @param keyOrder The desired order for top-level keys.
     * @return The YAML string, or {@code null}
     */
    public static String toYaml(JsonNode document, List<String> keyOrder) {
        if (document == null) {
            return null;
        }
        if (!document.isObject()) {
            return toYaml(document);
        }
        try {
            Map<String, Object> ordered = new LinkedHashMap<>();

            // Add keys in the requested order
            for (String key : keyOrder) {
                if (document.has(key)) {
                    ordered.put(key, document.get(key));
                }
            }

            // Add remaining keys
            Iterator<Map.Entry<String, JsonNode>> fields = document.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                if (!keyOrder.contains(field.getKey())) {
                    ordered.put(field.getKey(), field.getValue());
                }
            }

            return YAML_MAPPER.writeValueAsString(ordered);
        } catch (JsonProcessingException e) {
            log.error("Failed to serialize document to YAML with key ordering: {}", e.getMessage(), e);
            return null;
        }
    }

    /**
     * Parses a YAML string into a {@link JsonNode}.
     *
     * <p>Floats are preserved as {@link java.math.BigDecimal} to maintain type fidelity. A
     * post-processing step ensures that floating-point values like {@code 5.0} retain at least scale
     * 1 in their {@link BigDecimal} representation, preventing coercion to integer form.
     *
     * @param yaml The YAML string to parse.
     * @return The parsed {@link JsonNode}.
     * @throws IOException If parsing fails.
     */
    public static JsonNode fromYaml(String yaml) throws IOException {
        JsonNode tree = YAML_MAPPER.readTree(yaml);
        fixDecimalScale(tree);
        return tree;
    }

    /**
     * Recursively walks a {@link JsonNode} tree and fixes {@link DecimalNode} values that have scale
     * 0. In YAML, a value like {@code 5.0} is a float, but Jackson's YAML parser may create a {@link
     * BigDecimal} with scale 0, causing it to serialize as {@code 5} instead of {@code 5.0}. This
     * method sets the minimum scale to 1 for such nodes.
     *
     * <p>Integer values in YAML produce {@code IntNode}/{@code LongNode}, not {@code DecimalNode}, so
     * this fix only affects values that were genuinely floating-point in the source YAML.
     *
     * @param node The root node to process.
     */
    public static void fixDecimalScale(JsonNode node) {
        if (node == null) {
            return;
        }
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = obj.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> field = fields.next();
                JsonNode value = field.getValue();
                if (value.isFloatingPointNumber() && value.decimalValue().scale() <= 0) {
                    BigDecimal fixed = value.decimalValue().setScale(1);
                    obj.set(field.getKey(), DecimalNode.valueOf(fixed));
                } else {
                    fixDecimalScale(value);
                }
            }
        } else if (node.isArray()) {
            ArrayNode arr = (ArrayNode) node;
            for (int i = 0; i < arr.size(); i++) {
                JsonNode value = arr.get(i);
                if (value.isFloatingPointNumber() && value.decimalValue().scale() <= 0) {
                    BigDecimal fixed = value.decimalValue().setScale(1);
                    arr.set(i, DecimalNode.valueOf(fixed));
                } else {
                    fixDecimalScale(value);
                }
            }
        }
    }
}
