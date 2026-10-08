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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import java.util.EnumSet;
import java.util.List;
import java.util.Set;

import com.flipkart.zjsonpatch.CompatibilityFlags;
import com.flipkart.zjsonpatch.JsonPatchApplicationException;
import com.wazuh.contentmanager.cti.catalog.model.Operation;

/**
 * Applies the operations of a CTI change, which are JSON Patch (RFC 6902) operations, to a JSON
 * document.
 *
 * <p>Delegates to zjsonpatch, configured to follow the RFC strictly: an operation whose target
 * location does not exist fails.
 *
 * <p>The operations are applied in place: the document is not copied, so a change costs what it
 * modifies, whatever the size of the document. If an operation fails, the ones before it have
 * already been applied, so the caller must discard the document rather than store it. A replacement
 * of the whole document, which zjsonpatch cannot do in place, is handled here.
 */
public final class JsonPatch {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /**
     * RFC 6902 behaviour. zjsonpatch skips the removal of a missing object member unless told
     * otherwise; every other operation on a missing location fails by default.
     */
    private static final EnumSet<CompatibilityFlags> STRICT =
            EnumSet.of(CompatibilityFlags.FORBID_REMOVE_MISSING_OBJECT);

    /** The operations that take a value, which can be a JSON null. */
    private static final Set<String> VALUE_OPERATIONS = Set.of("add", "replace", "test");

    private JsonPatch() {}

    /** Thrown when an operation of a change is malformed or cannot be applied to the document. */
    public static class InvalidPatchException extends Exception {
        /**
         * Constructs a new InvalidPatchException.
         *
         * @param message Which operation failed, and why.
         * @param cause The library's failure.
         */
        public InvalidPatchException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Applies the operations of one change, in order, to a document, in place.
     *
     * @param document The document to patch. It is modified in place, and left partially patched if
     *     an operation fails.
     * @param operations The operations of the change.
     * @throws InvalidPatchException If an operation is malformed or cannot be applied. The message
     *     names the operation, by its position in the change, and its path.
     */
    public static void apply(JsonNode document, List<Operation> operations)
            throws InvalidPatchException {
        for (int i = 0; i < operations.size(); i++) {
            Operation operation = operations.get(i);
            try {
                if (replacesDocument(operation)) {
                    replaceDocument(document, operation);
                } else {
                    ArrayNode patch = MAPPER.createArrayNode().add(toJson(operation));
                    com.flipkart.zjsonpatch.JsonPatch.applyInPlace(patch, document, STRICT);
                }
            } catch (JsonPatchApplicationException | IllegalArgumentException e) {
                throw new InvalidPatchException(
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
    }

    /**
     * Whether an operation replaces the whole document: an {@code add} or {@code replace} of the root
     * ({@code path ""}). CTI publishes a new version of a resource this way.
     *
     * @param operation The operation.
     * @return {@code true} if it replaces the whole document.
     */
    private static boolean replacesDocument(Operation operation) {
        return "".equals(operation.getPath())
                && ("add".equals(operation.getOp()) || "replace".equals(operation.getOp()));
    }

    /**
     * Replaces the whole document in place. zjsonpatch cannot do it, since the caller holds the
     * reference to the root: the root object is emptied and filled with the new value's members.
     *
     * @param document The document.
     * @param operation An {@code add} or {@code replace} of the root.
     * @throws IllegalArgumentException If the document or the new value is not a JSON object.
     */
    private static void replaceDocument(JsonNode document, Operation operation) {
        JsonNode value = MAPPER.valueToTree(operation.getValue());
        if (!document.isObject() || value == null || !value.isObject()) {
            throw new IllegalArgumentException("the document can only be replaced by a JSON object");
        }
        ((ObjectNode) document).removeAll().setAll((ObjectNode) value);
    }

    /**
     * Converts an operation to its JSON Patch form.
     *
     * @param operation The operation.
     * @return The operation as a JSON object.
     */
    private static ObjectNode toJson(Operation operation) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put(Operation.OP, operation.getOp());
        node.put(Operation.PATH, operation.getPath());
        if (operation.getFrom() != null) {
            node.put(Operation.FROM, operation.getFrom());
        }
        if (operation.getOp() != null && VALUE_OPERATIONS.contains(operation.getOp())) {
            node.set(Operation.VALUE, MAPPER.valueToTree(operation.getValue()));
        }
        return node;
    }
}
