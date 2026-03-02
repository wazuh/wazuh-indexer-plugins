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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.cti.catalog.model.Operation;

/** Tests for the JsonPatch utility class. Validates JSON Patch operations. */
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class JsonPatchTests extends OpenSearchTestCase {

    private ObjectMapper mapper;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mapper = new ObjectMapper();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /** Test the add operation */
    public void testApplyOperationAdd() {
        ObjectNode document = this.mapper.createObjectNode();
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "add");
        operation.put(Operation.PATH, "/newField");
        operation.put(Operation.VALUE, "newValue");
        JsonPatch.applyOperation(document, operation);
        Assert.assertTrue(document.has("newField"));
        Assert.assertEquals("newValue", document.get("newField").asText());
    }

    /** Test the add operation on arrays */
    public void testApplyOperationAddToArray() {
        ObjectNode document = this.mapper.createObjectNode();
        ArrayNode array = this.mapper.createArrayNode();
        array.add("a");
        array.add("c");
        document.set("arr", array);

        // Test Insert at index 1
        ObjectNode insertOp = this.mapper.createObjectNode();
        insertOp.put(Operation.OP, "add");
        insertOp.put(Operation.PATH, "/arr/1");
        insertOp.put(Operation.VALUE, "b");
        JsonPatch.applyOperation(document, insertOp);

        ArrayNode updatedArray = (ArrayNode) document.get("arr");
        Assert.assertEquals(3, updatedArray.size());
        Assert.assertEquals("a", updatedArray.get(0).asText());
        Assert.assertEquals("b", updatedArray.get(1).asText());
        Assert.assertEquals("c", updatedArray.get(2).asText());

        // Test Append to end using "-"
        ObjectNode appendOp = this.mapper.createObjectNode();
        appendOp.put(Operation.OP, "add");
        appendOp.put(Operation.PATH, "/arr/-");
        appendOp.put(Operation.VALUE, "d");
        JsonPatch.applyOperation(document, appendOp);

        updatedArray = (ArrayNode) document.get("arr");
        Assert.assertEquals(4, updatedArray.size());
        Assert.assertEquals("d", updatedArray.get(3).asText());
    }

    /** Test the remove operation */
    public void testApplyOperationRemove() {
        ObjectNode document = this.mapper.createObjectNode();
        document.put("fieldToRemove", "value");
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "remove");
        operation.put(Operation.PATH, "/fieldToRemove");
        JsonPatch.applyOperation(document, operation);
        Assert.assertFalse(document.has("fieldToRemove"));
    }

    /** Test the remove operation on arrays */
    public void testApplyOperationRemoveFromArray() {
        ObjectNode document = this.mapper.createObjectNode();
        ArrayNode array = this.mapper.createArrayNode();
        array.add("a");
        array.add("b");
        array.add("c");
        document.set("arr", array);

        // Remove index 1 ("b")
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "remove");
        operation.put(Operation.PATH, "/arr/1");
        JsonPatch.applyOperation(document, operation);

        ArrayNode updatedArray = (ArrayNode) document.get("arr");
        Assert.assertEquals(2, updatedArray.size());
        Assert.assertEquals("a", updatedArray.get(0).asText());
        Assert.assertEquals("c", updatedArray.get(1).asText());
    }

    /** Test the replace operation */
    public void testApplyOperationReplace() {
        ObjectNode document = this.mapper.createObjectNode();
        document.put("fieldToReplace", "oldValue");
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "replace");
        operation.put(Operation.PATH, "/fieldToReplace");
        operation.put(Operation.VALUE, "newValue");
        JsonPatch.applyOperation(document, operation);
        Assert.assertEquals("newValue", document.get("fieldToReplace").asText());
    }

    /** Test the replace operation on arrays */
    public void testApplyOperationReplaceInArray() {
        ObjectNode document = this.mapper.createObjectNode();
        ArrayNode array = this.mapper.createArrayNode();
        array.add("a");
        array.add("b");
        document.set("arr", array);

        // Replace index 0 ("a") with "z"
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "replace");
        operation.put(Operation.PATH, "/arr/0");
        operation.put(Operation.VALUE, "z");
        JsonPatch.applyOperation(document, operation);

        ArrayNode updatedArray = (ArrayNode) document.get("arr");
        Assert.assertEquals(2, updatedArray.size());
        Assert.assertEquals("z", updatedArray.get(0).asText());
        Assert.assertEquals("b", updatedArray.get(1).asText());
    }

    /** Test the move operation */
    public void testApplyOperationMove() {
        ObjectNode document = this.mapper.createObjectNode();
        document.put("fieldToMove", "value");
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "move");
        operation.put(Operation.FROM, "/fieldToMove");
        operation.put(Operation.PATH, "/newField");
        JsonPatch.applyOperation(document, operation);
        Assert.assertFalse(document.has("fieldToMove"));
        Assert.assertTrue(document.has("newField"));
    }

    /** Test the move operation on arrays */
    public void testApplyOperationMoveInArray() {
        ObjectNode document = this.mapper.createObjectNode();
        ArrayNode array = this.mapper.createArrayNode();
        array.add("a");
        array.add("b");
        array.add("c");
        document.set("arr", array);

        // Move index 0 ("a") to index 2
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "move");
        operation.put(Operation.FROM, "/arr/0");
        operation.put(Operation.PATH, "/arr/2");
        JsonPatch.applyOperation(document, operation);

        ArrayNode updatedArray = (ArrayNode) document.get("arr");
        Assert.assertEquals(3, updatedArray.size());
        Assert.assertEquals("b", updatedArray.get(0).asText());
        Assert.assertEquals("c", updatedArray.get(1).asText());
        Assert.assertEquals("a", updatedArray.get(2).asText());
    }

    /** Test the copy operation */
    public void testApplyOperationCopy() {
        ObjectNode document = this.mapper.createObjectNode();
        document.put("fieldToCopy", "value");
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "copy");
        operation.put(Operation.FROM, "/fieldToCopy");
        operation.put(Operation.PATH, "/newField");
        JsonPatch.applyOperation(document, operation);
        Assert.assertTrue(document.has("newField"));
        Assert.assertEquals("value", document.get("newField").asText());
    }

    /** Test the copy operation on arrays */
    public void testApplyOperationCopyInArray() {
        ObjectNode document = this.mapper.createObjectNode();
        ArrayNode array = this.mapper.createArrayNode();
        array.add("a");
        array.add("b");
        document.set("arr", array);

        // Copy index 0 ("a") to end ("-")
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "copy");
        operation.put(Operation.FROM, "/arr/0");
        operation.put(Operation.PATH, "/arr/-");
        JsonPatch.applyOperation(document, operation);

        ArrayNode updatedArray = (ArrayNode) document.get("arr");
        Assert.assertEquals(3, updatedArray.size());
        Assert.assertEquals("a", updatedArray.get(0).asText());
        Assert.assertEquals("b", updatedArray.get(1).asText());
        Assert.assertEquals("a", updatedArray.get(2).asText());
    }

    /** Test the test operation */
    public void testApplyOperationTest() {
        ObjectNode document = this.mapper.createObjectNode();
        document.put("fieldToTest", "value");
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "test");
        operation.put(Operation.PATH, "/fieldToTest");
        operation.put(Operation.VALUE, "value");
        JsonPatch.applyOperation(document, operation);
        Assert.assertTrue(document.has("fieldToTest"));
    }

    /** Test the test operation on arrays */
    public void testApplyOperationTestInArray() {
        ObjectNode document = this.mapper.createObjectNode();
        ArrayNode array = this.mapper.createArrayNode();
        array.add("a");
        array.add("b");
        document.set("arr", array);

        // Test index 1 is "b" (PASS)
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "test");
        operation.put(Operation.PATH, "/arr/1");
        operation.put(Operation.VALUE, "b");
        JsonPatch.applyOperation(document, operation);

        // Test index 1 is "a" (FAILS)
        ObjectNode failOperation = this.mapper.createObjectNode();
        failOperation.put(Operation.OP, "test");
        failOperation.put(Operation.PATH, "/arr/1");
        failOperation.put(Operation.VALUE, "a");

        try {
            JsonPatch.applyOperation(document, failOperation);
            Assert.fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException ignored) {

        }
    }

    /** Test the unsupported operation */
    public void testApplyOperationUnsupported() {
        ObjectNode document = this.mapper.createObjectNode();
        ObjectNode operation = this.mapper.createObjectNode();
        operation.put(Operation.OP, "unsupported");
        operation.put(Operation.PATH, "/field");
        IllegalArgumentException exception =
                Assert.assertThrows(
                        IllegalArgumentException.class,
                        () -> {
                            JsonPatch.applyOperation(document, operation);
                        });
        Assert.assertEquals("Unsupported JSON Patch operation: unsupported", exception.getMessage());
    }
}
