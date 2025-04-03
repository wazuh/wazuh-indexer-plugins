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
package com.wazuh.contentmanager.util;

import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

public class JsonPatch {
    private static final Logger log = LogManager.getLogger(JsonPatch.class);

    /**
     * Applies a single JSON Patch operation to a document.
     *
     * @param document The target JSON document.
     * @param operation The JSON Patch operation.
     */
    private void applyPatchOperation(JsonObject document, JsonObject operation) {
        String op = operation.get("op").getAsString();
        String path = operation.get("path").getAsString();
        JsonElement value = operation.has("value") ? operation.get("value") : null;

        switch (op) {
            case "add":
                addOperation(document, path, value);
                break;
            case "remove":
                removeOperation(document, path);
                break;
            case "replace":
                replaceOperation(document, path, value);
                break;
            case "move":
                moveOperation(document, path, value);
                break;
            case "copy":
                copyOperation(document, path, value);
                break;
            case "test":
                testOperation(document, path, value);
                break;
            default:
                log.warn("Unsupported JSON Patch operation: {}", op);
        }
    }

    /** Handles the "add" operation. */
    private void addOperation(JsonObject document, String path, JsonElement value) {
        JsonElement target = navigateToParent(document, path);
        if (target instanceof JsonObject) {
            String key = extractKeyFromPath(path);
            ((JsonObject) target).add(key, value);
        }
    }

    /** Handles the "remove" operation. */
    private void removeOperation(JsonObject document, String path) {
        JsonElement target = navigateToParent(document, path);
        if (target instanceof JsonObject) {
            String key = extractKeyFromPath(path);
            ((JsonObject) target).remove(key);
        }
    }

    /** Handles the "replace" operation. */
    private void replaceOperation(JsonObject document, String path, JsonElement value) {
        removeOperation(document, path);
        addOperation(document, path, value);
    }

    /** Handles the "move" operation. */
    private void moveOperation(JsonObject document, String fromPath, String toPath) {
        JsonElement value = navigateToParent(document, fromPath);
        removeOperation(document, fromPath);
        addOperation(document, toPath, value);
    }

    /** Handles the "copy" operation. */
    private void copyOperation(JsonObject document, String fromPath, String toPath) {
        JsonElement value = navigateToParent(document, fromPath);
        addOperation(document, toPath, value);
    }

    /** Handles the "test" operation. */
    private void testOperation(JsonObject document, String path, JsonElement value) {
        JsonElement target = navigateToParent(document, path);
        if (target instanceof JsonObject) {
            String key = extractKeyFromPath(path);
            if (!((JsonObject) target).get(key).equals(value)) {
                throw new IllegalArgumentException("Test operation failed: value does not match");
            }
        }
    }

    /**
     * Applies a JSON Patch to a document.
     *
     * @param document The target JSON document.
     * @param patch The JSON Patch operations.
     */
    public void applyPatch(JsonObject document, JsonObject patch) {
        for (JsonElement operation : patch.getAsJsonArray("operations")) {
            applyPatchOperation(document, operation.getAsJsonObject());
        }
    }

    /** Navigates to the parent JSON element based on the given path. */
    private JsonElement navigateToParent(JsonObject document, String path) {
        String[] parts = path.split("/");
        JsonElement current = document;
        for (int i = 1; i < parts.length - 1; i++) { // Navigate to parent
            current = ((JsonObject) current).get(parts[i]);
        }
        return current;
    }

    /** Extracts the last key from the JSON path. */
    private String extractKeyFromPath(String path) {
        String[] parts = path.split("/");
        return parts[parts.length - 1];
    }
}
