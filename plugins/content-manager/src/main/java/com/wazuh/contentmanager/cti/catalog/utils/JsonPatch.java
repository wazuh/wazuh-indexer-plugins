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
package com.wazuh.contentmanager.cti.catalog.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wazuh.contentmanager.cti.catalog.model.Operation;

/**
 * Utility class for applying JSON Patch operations to JSON documents using Jackson.
 *
 * <p>This class provides methods to apply various JSON Patch operations such as add, remove,
 * replace, move, copy, and test.
 */
public class JsonPatch {
    private static final Logger log = LogManager.getLogger(JsonPatch.class);

    /**
     * Applies a single JSON Patch operation to a document.
     *
     * @param document The target JSON document.
     * @param operation The JSON Patch operation.
     */
    public static void applyOperation(ObjectNode document, JsonNode operation) {
        String op = operation.get(Operation.OP).asText();
        String path = operation.get(Operation.PATH).asText();
        JsonNode value = operation.has(Operation.VALUE) ? operation.get(Operation.VALUE) : null;
        String from = operation.has(Operation.FROM) ? operation.get(Operation.FROM).asText() : null;

        switch (op) {
            case "add":
                JsonPatch.addOperation(document, path, value);
                break;
            case "remove":
                JsonPatch.removeOperation(document, path);
                break;
            case "replace":
                JsonPatch.replaceOperation(document, path, value);
                break;
            case "move":
                JsonPatch.moveOperation(document, from, path);
                break;
            case "copy":
                JsonPatch.copyOperation(document, from, path);
                break;
            case "test":
                JsonPatch.testOperation(document, path, value);
                break;
            default:
                log.error("Unsupported JSON Patch operation: {}", op);
                throw new IllegalArgumentException("Unsupported JSON Patch operation: " + op);
        }
    }

    /**
     * Handles the "add" operation.
     *
     * @param document The target JSON document.
     * @param path The JSON path where the value should be added.
     * @param value The value to be added.
     */
    private static void addOperation(ObjectNode document, String path, JsonNode value) {
        if (path.isEmpty()) {
            document.removeAll();
            if (value != null && value.isObject()) {
                document.setAll((ObjectNode) value);
            }
            return;
        }

        JsonNode target = JsonPatch.navigateToParent(document, path);
        String key = JsonPatch.extractKeyFromPath(path);

        if (target instanceof ObjectNode objNode) {
            objNode.set(key, value);
        } else if (target instanceof ArrayNode arrayNode) {
            if ("-".equals(key)) {
                arrayNode.add(value);
            } else {
                try {
                    int index = Integer.parseInt(key);
                    if (index >= 0 && index <= arrayNode.size()) {
                        arrayNode.insert(index, value);
                    } else {
                        log.error("Index out of bounds for add operation: {}", index);
                        throw new IndexOutOfBoundsException("Index out of bounds for add operation: " + index);
                    }
                } catch (NumberFormatException e) {
                    log.error("Invalid array index for add operation: {}", key);
                    throw new IllegalArgumentException("Invalid array index for add operation: " + key);
                }
            }
        } else {
            log.error("Target for add operation is not a container");
            throw new IllegalArgumentException("Target for add operation is not a container");
        }
    }

    /**
     * Handles the "remove" operation.
     *
     * @param document The target JSON document.
     * @param path The JSON path where the value should be removed.
     */
    private static void removeOperation(ObjectNode document, String path) {
        if (path.isEmpty()) {
            document.removeAll();
            return;
        }

        JsonNode target = JsonPatch.navigateToParent(document, path);
        String key = JsonPatch.extractKeyFromPath(path);

        if (target instanceof ObjectNode objNode) {
            if (!objNode.has(key)) {
                log.error("Path not found for remove operation: {}", path);
                throw new IllegalArgumentException("Path not found for remove operation: " + path);
            }
            objNode.remove(key);
        } else if (target instanceof ArrayNode arrayNode) {
            try {
                int index = Integer.parseInt(key);
                if (index >= 0 && index < arrayNode.size()) {
                    arrayNode.remove(index);
                } else {
                    log.error("Index out of bounds for remove operation: {}", index);
                    throw new IndexOutOfBoundsException("Index out of bounds for remove operation: " + index);
                }
            } catch (NumberFormatException e) {
                log.error("Invalid array index for remove operation: {}", key);
                throw new IllegalArgumentException("Invalid array index for remove operation: " + key);
            }
        } else {
            log.error("Target for remove operation is not a container");
            throw new IllegalArgumentException("Target for remove operation is not a container");
        }
    }

    /**
     * Handles the "replace" operation.
     *
     * @param document The target JSON document.
     * @param path The JSON path where the value should be replaced.
     * @param value The new value to be added.
     */
    private static void replaceOperation(ObjectNode document, String path, JsonNode value) {
        JsonPatch.removeOperation(document, path);
        JsonPatch.addOperation(document, path, value);
    }

    /**
     * Handles the "move" operation.
     *
     * @param document The target JSON document.
     * @param fromPath The JSON path from where the value should be moved.
     * @param toPath The JSON path where the value should be moved.
     */
    private static void moveOperation(ObjectNode document, String fromPath, String toPath) {
        JsonNode parent = JsonPatch.navigateToParent(document, fromPath);
        if (parent == null) {
            log.error("Invalid 'from' path for move operation: {}", fromPath);
            throw new IllegalArgumentException("Invalid 'from' path for move operation: " + fromPath);
        }

        String key = JsonPatch.extractKeyFromPath(fromPath);
        JsonNode value = null;

        if (parent.isObject()) {
            if (!parent.has(key)) {
                log.error(
                        "Source key '{}' does not exist in 'from' path '{}', in move operation", key, fromPath);
                throw new IllegalArgumentException(
                        "Source key '"
                                + key
                                + "' does not exist in 'from' path '"
                                + fromPath
                                + "', in move operation");
            }
            value = parent.get(key);
        } else if (parent.isArray()) {
            try {
                int index = Integer.parseInt(key);
                ArrayNode array = (ArrayNode) parent;
                if (index >= 0 && index < array.size()) {
                    value = array.get(index);
                } else {
                    log.error("Index out of bounds for move operation: {}", index);
                    throw new IndexOutOfBoundsException("Index out of bounds for move operation: " + index);
                }
            } catch (NumberFormatException e) {
                log.error("Invalid array index for move operation: {}", key);
                throw new IllegalArgumentException("Invalid array index for move operation: " + key);
            }
        }

        if (value == null) {
            log.error("Could not retrieve value to move from: {}", fromPath);
            throw new IllegalArgumentException("Could not retrieve value to move from: " + fromPath);
        }

        JsonPatch.removeOperation(document, fromPath);
        JsonPatch.addOperation(document, toPath, value);
    }

    /**
     * Handles the "copy" operation.
     *
     * @param document The target JSON document.
     * @param fromPath The JSON path from where the value should be copied.
     * @param toPath The JSON path where the value should be copied.
     */
    private static void copyOperation(ObjectNode document, String fromPath, String toPath) {
        JsonNode parent = JsonPatch.navigateToParent(document, fromPath);
        if (parent == null) {
            log.error("Invalid 'from' path for copy operation: {}", fromPath);
            throw new IllegalArgumentException("Invalid 'from' path for copy operation: " + fromPath);
        }

        String fromKey = JsonPatch.extractKeyFromPath(fromPath);
        JsonNode valueToCopy = null;

        if (parent.isObject()) {
            if (!parent.has(fromKey)) {
                log.error(
                        "Source key '{}' does not exist in 'from' path '{}', in copy operation",
                        fromKey,
                        fromPath);
                throw new IllegalArgumentException(
                        "Source key '"
                                + fromKey
                                + "' does not exist in 'from' path '"
                                + fromPath
                                + "', in copy operation");
            }
            valueToCopy = parent.get(fromKey);
        } else if (parent.isArray()) {
            try {
                int index = Integer.parseInt(fromKey);
                ArrayNode array = (ArrayNode) parent;
                if (index >= 0 && index < array.size()) {
                    valueToCopy = array.get(index);
                } else {
                    log.error("Index out of bounds for copy operation: {}", index);
                    throw new IndexOutOfBoundsException("Index out of bounds for copy operation: " + index);
                }
            } catch (NumberFormatException e) {
                log.error("Invalid array index for copy operation: {}", fromKey);
                throw new IllegalArgumentException("Invalid array index for copy operation: " + fromKey);
            }
        }

        if (valueToCopy == null) {
            log.error("Could not retrieve value to copy from: {}", fromPath);
            throw new IllegalArgumentException("Could not retrieve value to copy from: " + fromPath);
        }

        JsonNode copiedValue = valueToCopy.deepCopy();
        JsonPatch.addOperation(document, toPath, copiedValue);
    }

    /**
     * Handles the "test" operation.
     *
     * @param document The target JSON document.
     * @param path The JSON path where the value should be tested.
     * @param value The expected value to be tested against.
     * @throws IllegalArgumentException if the value does not match.
     */
    private static void testOperation(ObjectNode document, String path, JsonNode value) {
        JsonNode target = JsonPatch.navigateToParent(document, path);
        if (target == null) {
            log.error("Path not found for test operation: {}", path);
            throw new IllegalArgumentException("Path not found for test operation: " + path);
        }

        String key = JsonPatch.extractKeyFromPath(path);
        JsonNode actual = null;

        if (target instanceof ObjectNode) {
            actual = target.get(key);
        } else if (target instanceof ArrayNode array) {
            try {
                int index = Integer.parseInt(key);
                if (index >= 0 && index < array.size()) {
                    actual = array.get(index);
                } else {
                    log.error("Index out of bounds for test operation: {}", index);
                    throw new IndexOutOfBoundsException("Index out of bounds for test operation: " + index);
                }
            } catch (NumberFormatException e) {
                log.error("Invalid array index for test operation: {}", key);
                throw new IllegalArgumentException("Invalid array index for test operation: " + key);
            }
        }

        if (actual == null || !actual.equals(value)) {
            log.error("Test operation failed: value does not match");
            throw new IllegalArgumentException("Test operation failed: value does not match");
        }
    }

    /**
     * Navigates to the parent JSON element based on the given path.
     *
     * @param document The target JSON document.
     * @param path The JSON path to navigate.
     * @return The parent JSON element.
     */
    private static JsonNode navigateToParent(ObjectNode document, String path) {
        String[] parts = path.split("/");
        JsonNode current = document;

        for (int i = 1; i < parts.length - 1; i++) {
            String part = parts[i];
            if (current == null) {
                return null;
            }

            if (current instanceof ObjectNode obj) {
                current = obj.has(part) ? obj.get(part) : null;
            } else if (current instanceof ArrayNode arr) {
                try {
                    int index = Integer.parseInt(part);
                    current = (index >= 0 && index < arr.size()) ? arr.get(index) : null;
                } catch (NumberFormatException e) {
                    return null;
                }
            } else {
                return null;
            }
        }
        return current;
    }

    /**
     * Extracts the last key from the JSON path.
     *
     * @param path The JSON path.
     * @return The last key in the path.
     */
    private static String extractKeyFromPath(String path) {
        String[] parts = path.split("/");
        return parts[parts.length - 1];
    }
}
