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
package com.wazuh.contentmanager.cti.catalog.utils;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wazuh.contentmanager.cti.catalog.model.Operation;

/**
 * Utility class for applying JSON Patch operations to JSON documents.
 *
 * <p>This class provides methods to apply various JSON Patch operations such as add, remove,
 * replace, move, copy, and test. It uses the Gson library for JSON manipulation.
 */
public class JsonPatch {
    private static final Logger log = LogManager.getLogger(JsonPatch.class);

    /**
     * Applies a single JSON Patch operation to a document.
     *
     * @param document The target JSON document.
     * @param operation The JSON Patch operation.
     */
    public static void applyOperation(JsonObject document, JsonObject operation) {
        String op = operation.get(Operation.OP).getAsString();
        String path = operation.get(Operation.PATH).getAsString();
        JsonElement value = operation.has(Operation.VALUE) ? operation.get(Operation.VALUE) : null;
        String from =
                operation.has(Operation.FROM) ? operation.get(Operation.FROM).getAsString() : null;

        // TODO replace with Operation.Type
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
                log.warn("Unsupported JSON Patch operation: {}", op);
                break;
        }
    }

    /**
     * Handles the "add" operation.
     *
     * @param document The target JSON document.
     * @param path The JSON path where the value should be added.
     * @param value The value to be added.
     */
    private static void addOperation(JsonObject document, String path, JsonElement value) {
        JsonElement target = JsonPatch.navigateToParent(document, path);
        if (target instanceof JsonObject) {
            String key = extractKeyFromPath(path);
            ((JsonObject) target).add(key, value);
        }
    }

    /**
     * Handles the "remove" operation.
     *
     * @param document The target JSON document.
     * @param path The JSON path where the value should be removed.
     */
    private static void removeOperation(JsonObject document, String path) {
        JsonElement target = JsonPatch.navigateToParent(document, path);
        if (target instanceof JsonObject) {
            String key = extractKeyFromPath(path);
            ((JsonObject) target).remove(key);
        }
    }

    /**
     * Handles the "replace" operation.
     *
     * @param document The target JSON document.
     * @param path The JSON path where the value should be replaced.
     * @param value The new value to be added.
     */
    private static void replaceOperation(JsonObject document, String path, JsonElement value) {
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
    private static void moveOperation(JsonObject document, String fromPath, String toPath) {
        JsonElement value = navigateToParent(document, fromPath);
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
    private static void copyOperation(JsonObject document, String fromPath, String toPath) {
        JsonElement parent = JsonPatch.navigateToParent(document, fromPath);
        if (parent == null || !parent.isJsonObject()) {
            log.error("Invalid 'from' path for copy operation: {}", fromPath);
            return;
        }

        String fromKey = extractKeyFromPath(fromPath);
        if (!parent.getAsJsonObject().has(fromKey)) {
            log.error("Source key '{}' does not exist in 'from' path '{}'", fromKey, fromPath);
            return;
        }

        // Get the actual value to copy
        JsonElement valueToCopy = parent.getAsJsonObject().get(fromKey);
        // Deep copy to avoid reference issues
        JsonElement copiedValue = valueToCopy.deepCopy();
        // Now add the copied value to the new location
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
    private static void testOperation(JsonObject document, String path, JsonElement value) {
        JsonElement target = JsonPatch.navigateToParent(document, path);
        if (target instanceof JsonObject) {
            String key = JsonPatch.extractKeyFromPath(path);
            if (!((JsonObject) target).get(key).equals(value)) {
                throw new IllegalArgumentException("Test operation failed: value does not match");
            }
        }
    }

    /**
     * Navigates to the parent JSON element based on the given path.
     *
     * @param document The target JSON document.
     * @param path The JSON path to navigate.
     * @return The parent JSON element.
     */
    private static JsonElement navigateToParent(JsonObject document, String path) {
        String[] parts = path.split("/");
        JsonElement current = document;

        for (int i = 1; i < parts.length - 1; i++) { // Navigate to parent object
            if (current.isJsonObject()) {
                JsonObject obj = current.getAsJsonObject();
                if (!obj.has(parts[i])) {
                    return null; // Path does not exist
                }
                current = obj.get(parts[i]);
            } else {
                return null; // Trying to navigate inside a non-object
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
