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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import com.wazuh.contentmanager.cti.catalog.model.Operation;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class JsonPatchTests extends OpenSearchTestCase {

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
    }

    /** Test the add operation */
    public void testApplyOperationAdd() {
        JsonObject document = new JsonObject();
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "add");
        operation.addProperty(Operation.PATH, "/newField");
        operation.addProperty(Operation.VALUE, "newValue");
        JsonPatch.applyOperation(document, operation);
        assertTrue(document.has("newField"));
        assertEquals("newValue", document.get("newField").getAsString());
    }

    /** Test the add operation on arrays */
    public void testApplyOperationAddToArray() {
        JsonObject document = new JsonObject();
        JsonArray array = new JsonArray();
        array.add("a");
        array.add("c");
        document.add("arr", array);

        // Test Insert at index 1
        JsonObject insertOp = new JsonObject();
        insertOp.addProperty(Operation.OP, "add");
        insertOp.addProperty(Operation.PATH, "/arr/1");
        insertOp.addProperty(Operation.VALUE, "b");
        JsonPatch.applyOperation(document, insertOp);

        JsonArray updatedArray = document.getAsJsonArray("arr");
        assertEquals(3, updatedArray.size());
        assertEquals("a", updatedArray.get(0).getAsString());
        assertEquals("b", updatedArray.get(1).getAsString());
        assertEquals("c", updatedArray.get(2).getAsString());

        // Test Append to end using "-"
        JsonObject appendOp = new JsonObject();
        appendOp.addProperty(Operation.OP, "add");
        appendOp.addProperty(Operation.PATH, "/arr/-");
        appendOp.addProperty(Operation.VALUE, "d");
        JsonPatch.applyOperation(document, appendOp);

        updatedArray = document.getAsJsonArray("arr");
        assertEquals(4, updatedArray.size());
        assertEquals("d", updatedArray.get(3).getAsString());
    }

    /** Test the remove operation */
    public void testApplyOperationRemove() {
        JsonObject document = new JsonObject();
        document.addProperty("fieldToRemove", "value");
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "remove");
        operation.addProperty(Operation.PATH, "/fieldToRemove");
        JsonPatch.applyOperation(document, operation);
        assertFalse(document.has("fieldToRemove"));
    }

    /** Test the remove operation on arrays */
    public void testApplyOperationRemoveFromArray() {
        JsonObject document = new JsonObject();
        JsonArray array = new JsonArray();
        array.add("a");
        array.add("b");
        array.add("c");
        document.add("arr", array);

        // Remove index 1 ("b")
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "remove");
        operation.addProperty(Operation.PATH, "/arr/1");
        JsonPatch.applyOperation(document, operation);

        JsonArray updatedArray = document.getAsJsonArray("arr");
        assertEquals(2, updatedArray.size());
        assertEquals("a", updatedArray.get(0).getAsString());
        assertEquals("c", updatedArray.get(1).getAsString());
    }

    /** Test the replace operation */
    public void testApplyOperationReplace() {
        JsonObject document = new JsonObject();
        document.addProperty("fieldToReplace", "oldValue");
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "replace");
        operation.addProperty(Operation.PATH, "/fieldToReplace");
        operation.addProperty(Operation.VALUE, "newValue");
        JsonPatch.applyOperation(document, operation);
        assertEquals("newValue", document.get("fieldToReplace").getAsString());
    }

    /** Test the replace operation on arrays */
    public void testApplyOperationReplaceInArray() {
        JsonObject document = new JsonObject();
        JsonArray array = new JsonArray();
        array.add("a");
        array.add("b");
        document.add("arr", array);

        // Replace index 0 ("a") with "z"
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "replace");
        operation.addProperty(Operation.PATH, "/arr/0");
        operation.addProperty(Operation.VALUE, "z");
        JsonPatch.applyOperation(document, operation);

        JsonArray updatedArray = document.getAsJsonArray("arr");
        assertEquals(2, updatedArray.size());
        assertEquals("z", updatedArray.get(0).getAsString());
        assertEquals("b", updatedArray.get(1).getAsString());
    }

    /** Test the move operation */
    public void testApplyOperationMove() {
        JsonObject document = new JsonObject();
        document.addProperty("fieldToMove", "value");
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "move");
        operation.addProperty(Operation.FROM, "/fieldToMove");
        operation.addProperty(Operation.PATH, "/newField");
        JsonPatch.applyOperation(document, operation);
        assertFalse(document.has("fieldToMove"));
        assertTrue(document.has("newField"));
    }

    /** Test the move operation on arrays */
    public void testApplyOperationMoveInArray() {
        JsonObject document = new JsonObject();
        JsonArray array = new JsonArray();
        array.add("a");
        array.add("b");
        array.add("c");
        document.add("arr", array);

        // Move index 0 ("a") to index 2
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "move");
        operation.addProperty(Operation.FROM, "/arr/0");
        operation.addProperty(Operation.PATH, "/arr/2");
        JsonPatch.applyOperation(document, operation);

        JsonArray updatedArray = document.getAsJsonArray("arr");
        assertEquals(3, updatedArray.size());
        assertEquals("b", updatedArray.get(0).getAsString());
        assertEquals("c", updatedArray.get(1).getAsString());
        assertEquals("a", updatedArray.get(2).getAsString());
    }

    /** Test the copy operation */
    public void testApplyOperationCopy() {
        JsonObject document = new JsonObject();
        document.addProperty("fieldToCopy", "value");
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "copy");
        operation.addProperty(Operation.FROM, "/fieldToCopy");
        operation.addProperty(Operation.PATH, "/newField");
        JsonPatch.applyOperation(document, operation);
        assertTrue(document.has("newField"));
        assertEquals("value", document.get("newField").getAsString());
    }

    /** Test the copy operation on arrays */
    public void testApplyOperationCopyInArray() {
        JsonObject document = new JsonObject();
        JsonArray array = new JsonArray();
        array.add("a");
        array.add("b");
        document.add("arr", array);

        // Copy index 0 ("a") to end ("-")
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "copy");
        operation.addProperty(Operation.FROM, "/arr/0");
        operation.addProperty(Operation.PATH, "/arr/-");
        JsonPatch.applyOperation(document, operation);

        JsonArray updatedArray = document.getAsJsonArray("arr");
        assertEquals(3, updatedArray.size());
        assertEquals("a", updatedArray.get(0).getAsString());
        assertEquals("b", updatedArray.get(1).getAsString());
        assertEquals("a", updatedArray.get(2).getAsString());
    }

    /** Test the test operation */
    public void testApplyOperationTest() {
        JsonObject document = new JsonObject();
        document.addProperty("fieldToTest", "value");
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "test");
        operation.addProperty(Operation.PATH, "/fieldToTest");
        operation.addProperty(Operation.VALUE, "value");
        JsonPatch.applyOperation(document, operation);
        assertTrue(document.has("fieldToTest"));
    }

    /** Test the test operation on arrays */
    public void testApplyOperationTestInArray() {
        JsonObject document = new JsonObject();
        JsonArray array = new JsonArray();
        array.add("a");
        array.add("b");
        document.add("arr", array);

        // Test index 1 is "b" (PASS)
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "test");
        operation.addProperty(Operation.PATH, "/arr/1");
        operation.addProperty(Operation.VALUE, "b");
        JsonPatch.applyOperation(document, operation);

        // Test index 1 is "a" (FAILS)
        JsonObject failOperation = new JsonObject();
        failOperation.addProperty(Operation.OP, "test");
        failOperation.addProperty(Operation.PATH, "/arr/1");
        failOperation.addProperty(Operation.VALUE, "a");

        try {
            JsonPatch.applyOperation(document, failOperation);
            fail("Should have thrown IllegalArgumentException");
        } catch (IllegalArgumentException ignored) {

        }
    }

    /** Test the unsupported operation */
    public void testApplyOperationUnsupported() {
        JsonObject document = new JsonObject();
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "unsupported");
        operation.addProperty(Operation.PATH, "/field");
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            JsonPatch.applyOperation(document, operation);
        });
        assertEquals("Unsupported JSON Patch operation: unsupported", exception.getMessage());
    }
}
