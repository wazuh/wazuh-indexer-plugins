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
package com.wazuh.contentmanager.utils;

import com.google.gson.JsonObject;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import com.wazuh.contentmanager.model.cti.Operation;

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

    /** Test the unsupported operation */
    public void testApplyOperationUnsupported() {
        JsonObject document = new JsonObject();
        JsonObject operation = new JsonObject();
        operation.addProperty(Operation.OP, "unsupported");
        operation.addProperty(Operation.PATH, "/field");
        JsonPatch.applyOperation(document, operation);
        assertFalse(document.has("field"));
    }
}
