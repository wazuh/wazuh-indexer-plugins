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
import com.fasterxml.jackson.databind.ObjectMapper;

import com.github.fge.jackson.jsonpointer.JsonPointer;
import com.github.fge.jackson.jsonpointer.JsonPointerException;
import com.github.fge.jsonpatch.AddOperation;
import com.github.fge.jsonpatch.CopyOperation;
import com.github.fge.jsonpatch.JsonPatchException;
import com.github.fge.jsonpatch.JsonPatchOperation;
import com.github.fge.jsonpatch.MoveOperation;
import com.github.fge.jsonpatch.RemoveOperation;
import com.github.fge.jsonpatch.ReplaceOperation;
import com.github.fge.jsonpatch.TestOperation;

import java.util.List;

import com.wazuh.contentmanager.cti.catalog.model.Operation;

/**
 * Applies the operations of a CTI change, which are JSON Patch (RFC 6902) operations, to a JSON
 * document.
 *
 * <p>Delegates to the java-json-tools json-patch library, which follows the RFC strictly: an
 * operation whose target location does not exist fails, and so does the whole change. Each
 * operation works on a copy, so the document passed in is never modified, whether the change
 * applies or not.
 *
 * <p>The library's operations are built here rather than read from JSON: its reader turns
 * floating-point values into decimals without trailing zeros, so {@code 7.0} would be stored as
 * {@code 7}.
 */
public final class JsonPatch {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private JsonPatch() {}

    /**
     * Applies the operations of one change, in order, to a document.
     *
     * @param document The document to patch. It is not modified.
     * @param operations The operations of the change.
     * @return The patched document.
     * @throws JsonPatchException If an operation is malformed or cannot be applied. The message names
     *     the operation, by its position in the change, and its path.
     */
    public static JsonNode apply(JsonNode document, List<Operation> operations)
            throws JsonPatchException {
        JsonNode result = document;
        for (int i = 0; i < operations.size(); i++) {
            Operation operation = operations.get(i);
            try {
                result = toPatchOperation(operation).apply(result);
            } catch (JsonPointerException | JsonPatchException e) {
                throw new JsonPatchException(
                        "operation "
                                + i
                                + " ("
                                + operation.getOp()
                                + " "
                                + operation.getPath()
                                + "): "
                                + e.getMessage(),
                        e);
            }
        }
        return result;
    }

    /**
     * Converts an operation to the library's representation.
     *
     * @param operation The operation.
     * @return The library operation.
     * @throws JsonPointerException If {@code path} or {@code from} is not a valid JSON Pointer.
     * @throws JsonPatchException If the operation is unknown, or lacks {@code path} or {@code from}.
     */
    private static JsonPatchOperation toPatchOperation(Operation operation)
            throws JsonPointerException, JsonPatchException {
        JsonPointer path = pointer(Operation.PATH, operation.getPath());
        // add, replace and test take a value, which can be a JSON null.
        return switch (String.valueOf(operation.getOp())) {
            case "add" -> new AddOperation(path, MAPPER.valueToTree(operation.getValue()));
            case "remove" -> new RemoveOperation(path);
            case "replace" -> new ReplaceOperation(path, MAPPER.valueToTree(operation.getValue()));
            case "move" -> new MoveOperation(pointer(Operation.FROM, operation.getFrom()), path);
            case "copy" -> new CopyOperation(pointer(Operation.FROM, operation.getFrom()), path);
            case "test" -> new TestOperation(path, MAPPER.valueToTree(operation.getValue()));
            default -> throw new JsonPatchException("unsupported operation");
        };
    }

    /**
     * Parses a JSON Pointer of an operation.
     *
     * @param field The operation field the pointer comes from, for the error message.
     * @param pointer The pointer.
     * @return The parsed pointer.
     * @throws JsonPointerException If the pointer is not a valid JSON Pointer.
     * @throws JsonPatchException If the pointer is missing.
     */
    private static JsonPointer pointer(String field, String pointer)
            throws JsonPointerException, JsonPatchException {
        if (pointer == null) {
            throw new JsonPatchException("missing '" + field + "'");
        }
        return new JsonPointer(pointer);
    }
}
