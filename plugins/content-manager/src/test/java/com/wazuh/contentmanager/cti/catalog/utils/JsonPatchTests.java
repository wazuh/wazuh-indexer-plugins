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

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;
import org.junit.Before;

import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Operation;

/** Tests for the JsonPatch utility class. Validates JSON Patch (RFC 6902) operations. */
public class JsonPatchTests extends OpenSearchTestCase {

    private ObjectMapper mapper;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mapper = new ObjectMapper();
    }

    private JsonNode json(String json) throws Exception {
        return this.mapper.readTree(json.replace('\'', '"'));
    }

    private static Operation op(String op, String path, Object value) {
        return new Operation(op, path, null, value);
    }

    private static Operation fromOp(String op, String from, String path) {
        return new Operation(op, path, from, null);
    }

    /** Applies the operations to the document, which is patched in place, and returns it. */
    private static JsonNode patch(JsonNode document, List<Operation> operations)
            throws JsonPatch.InvalidPatchException {
        JsonPatch.apply(document, operations);
        return document;
    }

    /** Test the add operation */
    public void testApplyAdd() throws Exception {
        JsonNode result = patch(json("{}"), List.of(op("add", "/newField", "newValue")));
        Assert.assertEquals(json("{'newField':'newValue'}"), result);
    }

    /** Test the add operation on arrays: insert at an index, and append with "-" */
    public void testApplyAddToArray() throws Exception {
        JsonNode result =
                patch(
                        json("{'arr':['a','c']}"), List.of(op("add", "/arr/1", "b"), op("add", "/arr/-", "d")));
        Assert.assertEquals(json("{'arr':['a','b','c','d']}"), result);
    }

    /** Test the add operation with an object value and with an explicit JSON null */
    public void testApplyAddStructuredAndNullValues() throws Exception {
        JsonNode result =
                patch(
                        json("{}"),
                        List.of(op("add", "/obj", Map.of("k", List.of(1, 2))), op("add", "/nothing", null)));
        Assert.assertEquals(json("{'obj':{'k':[1,2]},'nothing':null}"), result);
    }

    /** Test the remove operation */
    public void testApplyRemove() throws Exception {
        JsonNode result =
                patch(
                        json("{'fieldToRemove':'value','kept':1}"),
                        List.of(new Operation("remove", "/fieldToRemove", null, null)));
        Assert.assertEquals(json("{'kept':1}"), result);
    }

    /** Test the remove operation on arrays */
    public void testApplyRemoveFromArray() throws Exception {
        JsonNode result =
                patch(
                        json("{'arr':['a','b','c']}"), List.of(new Operation("remove", "/arr/1", null, null)));
        Assert.assertEquals(json("{'arr':['a','c']}"), result);
    }

    /** Test the replace operation */
    public void testApplyReplace() throws Exception {
        JsonNode result =
                patch(
                        json("{'fieldToReplace':'oldValue'}"),
                        List.of(op("replace", "/fieldToReplace", "newValue")));
        Assert.assertEquals(json("{'fieldToReplace':'newValue'}"), result);
    }

    /** Test the replace operation on arrays */
    public void testApplyReplaceInArray() throws Exception {
        JsonNode result = patch(json("{'arr':['a','b']}"), List.of(op("replace", "/arr/0", "z")));
        Assert.assertEquals(json("{'arr':['z','b']}"), result);
    }

    /** Test the move operation */
    public void testApplyMove() throws Exception {
        JsonNode result =
                patch(
                        json("{'fieldToMove':'value'}"), List.of(fromOp("move", "/fieldToMove", "/newField")));
        Assert.assertEquals(json("{'newField':'value'}"), result);
    }

    /** Test the move operation on arrays */
    public void testApplyMoveInArray() throws Exception {
        JsonNode result =
                patch(json("{'arr':['a','b','c']}"), List.of(fromOp("move", "/arr/0", "/arr/2")));
        Assert.assertEquals(json("{'arr':['b','c','a']}"), result);
    }

    /** Test the copy operation */
    public void testApplyCopy() throws Exception {
        JsonNode result =
                patch(
                        json("{'fieldToCopy':'value'}"), List.of(fromOp("copy", "/fieldToCopy", "/newField")));
        Assert.assertEquals(json("{'fieldToCopy':'value','newField':'value'}"), result);
    }

    /** Test the copy operation on arrays */
    public void testApplyCopyInArray() throws Exception {
        JsonNode result = patch(json("{'arr':['a','b']}"), List.of(fromOp("copy", "/arr/0", "/arr/-")));
        Assert.assertEquals(json("{'arr':['a','b','a']}"), result);
    }

    /** Test the test operation, which passes on a matching value and fails otherwise */
    public void testApplyTest() throws Exception {
        JsonNode document = json("{'arr':['a','b']}");
        Assert.assertEquals(document, patch(document, List.of(op("test", "/arr/1", "b"))));
        Assert.assertThrows(
                JsonPatch.InvalidPatchException.class,
                () -> patch(document, List.of(op("test", "/arr/1", "a"))));
    }

    /**
     * CTI publishes a new version of a resource by replacing the whole document (path ""). The
     * document is replaced in place: the same object ends up with the new members only.
     */
    public void testApplyReplaceWholeDocument() throws Exception {
        JsonNode document = json("{'a':1,'b':{'c':2}}");

        JsonPatch.apply(document, List.of(op("replace", "", Map.of("d", List.of(3)))));

        Assert.assertEquals(json("{'d':[3]}"), document);
    }

    /** An add of the root replaces the whole document too. */
    public void testApplyAddWholeDocument() throws Exception {
        JsonNode document = json("{'a':1}");

        JsonPatch.apply(document, List.of(op("add", "", Map.of("b", 2)), op("add", "/c", 3)));

        Assert.assertEquals(json("{'b':2,'c':3}"), document);
    }

    /** A stored document is always an object, so the root cannot be replaced by anything else. */
    public void testApplyReplaceWholeDocumentWithNonObjectFails() throws Exception {
        JsonPatch.InvalidPatchException e =
                Assert.assertThrows(
                        JsonPatch.InvalidPatchException.class,
                        () -> JsonPatch.apply(json("{'a':1}"), List.of(op("replace", "", List.of(1)))));

        Assert.assertEquals(
                "operation 0 (replace ): the document can only be replaced by a JSON object",
                e.getMessage());
    }

    /** JSON Pointer escapes: "~1" stands for "/" and "~0" for "~" in a key. */
    public void testApplyEscapedKeys() throws Exception {
        JsonNode result =
                patch(
                        json("{'a/b':1,'c~d':2}"),
                        List.of(op("replace", "/a~1b", 10), op("replace", "/c~0d", 20)));
        Assert.assertEquals(json("{'a/b':10,'c~d':20}"), result);
    }

    /**
     * A floating-point value keeps its form: a CVSS score of 7.0 is stored as 7.0, not 7, as it is in
     * the CTI content.
     */
    public void testApplyKeepsWholeFloatingPointValues() throws Exception {
        JsonNode result =
                patch(
                        json("{'baseScore':5.5,'scores':[1.5]}"),
                        List.of(op("replace", "/baseScore", 7.0), op("add", "/scores/-", 10.0)));
        Assert.assertEquals(
                "{\"baseScore\":7.0,\"scores\":[1.5,10.0]}", this.mapper.writeValueAsString(result));
    }

    /** An operation without a path is rejected, naming the operation. */
    public void testApplyMissingPath() throws Exception {
        JsonPatch.InvalidPatchException e =
                Assert.assertThrows(
                        JsonPatch.InvalidPatchException.class,
                        () -> patch(json("{}"), List.of(op("add", null, "x"))));
        Assert.assertTrue(e.getMessage(), e.getMessage().startsWith("operation 0 (add null): "));
    }

    /** An unknown operation is rejected, naming the operation. */
    public void testApplyUnsupportedOperation() throws Exception {
        JsonPatch.InvalidPatchException e =
                Assert.assertThrows(
                        JsonPatch.InvalidPatchException.class,
                        () -> patch(json("{}"), List.of(op("unsupported", "/field", "x"))));
        Assert.assertTrue(
                e.getMessage(), e.getMessage().startsWith("operation 0 (unsupported /field): "));
    }

    /** Removing a missing field fails, as RFC 6902 section 4.2 requires. */
    public void testApplyRemoveMissingFieldFails() throws Exception {
        JsonPatch.InvalidPatchException e =
                Assert.assertThrows(
                        JsonPatch.InvalidPatchException.class,
                        () ->
                                patch(
                                        json("{'existing':'value'}"),
                                        List.of(new Operation("remove", "/nonexistent", null, null))));
        Assert.assertEquals(
                "operation 0 (remove /nonexistent): Missing field nonexistent", e.getMessage());
    }

    /** Removing an out-of-bounds array index fails. */
    public void testApplyRemoveArrayOutOfBoundsFails() {
        Assert.assertThrows(
                JsonPatch.InvalidPatchException.class,
                () ->
                        patch(
                                json("{'arr':['a','b']}"), List.of(new Operation("remove", "/arr/5", null, null))));
    }

    /** Replacing a missing field fails rather than adding it. */
    public void testApplyReplaceMissingFieldFails() {
        Assert.assertThrows(
                JsonPatch.InvalidPatchException.class,
                () -> patch(json("{}"), List.of(op("replace", "/missing", "x"))));
    }

    /**
     * When an operation fails, the exception names it by position and path. The document is patched
     * in place, so the operations before the failing one stay applied: callers discard it, as
     * ContentIndex does by never indexing a document whose change failed.
     */
    public void testApplyFailureNamesTheOperationAndLeavesEarlierOnesApplied() throws Exception {
        JsonNode document = json("{'a':1,'arr':['x']}");

        JsonPatch.InvalidPatchException e =
                Assert.assertThrows(
                        JsonPatch.InvalidPatchException.class,
                        () ->
                                patch(
                                        document,
                                        List.of(
                                                op("replace", "/a", 2),
                                                op("add", "/arr/0", "y"),
                                                op("add", "/missing/child", "z"))));

        Assert.assertTrue(
                e.getMessage(), e.getMessage().startsWith("operation 2 (add /missing/child): "));
        Assert.assertEquals(json("{'a':2,'arr':['y','x']}"), document);
    }

    // The CVE-2026-61372 change from issue #1632, reduced to the affected entries.
    private static final String CVE_PREVIOUS =
            "{'containers':{'adp':[{'affected':["
                    + "{'platforms':['bookworm','forky','sid'],'product':'libapache-jena-java'},"
                    + "{'platforms':['trixie'],'product':'apache-jena'}]}]}}";
    private static final String CVE_CURRENT =
            "{'containers':{'adp':[{'affected':["
                    + "{'platforms':['forky','sid'],'product':'libapache-jena-java'},"
                    + "{'platforms':['bookworm','trixie'],'product':'apache-jena'}]}]}}";
    private static final List<Operation> CVE_CHANGE =
            List.of(
                    op("add", "/containers/adp/0/affected/1/platforms/1", "trixie"),
                    op("replace", "/containers/adp/0/affected/1/platforms/0", "bookworm"),
                    new Operation("remove", "/containers/adp/0/affected/0/platforms/2", null, null),
                    op("replace", "/containers/adp/0/affected/0/platforms/1", "sid"),
                    op("replace", "/containers/adp/0/affected/0/platforms/0", "forky"));

    /** The change of issue #1632 turns the previous CTI version into the current one. */
    public void testApplyIssue1632Change() throws Exception {
        Assert.assertEquals(json(CVE_CURRENT), patch(json(CVE_PREVIOUS), CVE_CHANGE));
    }

    /**
     * Applied to an older version that lacks the second affected entry, the same change fails on its
     * first operation, which is what the indexer logged in issue #1632.
     */
    public void testApplyIssue1632ChangeToOlderVersionFails() throws Exception {
        JsonNode older =
                json(
                        "{'containers':{'adp':[{'affected':["
                                + "{'platforms':['bookworm','forky','sid'],'product':'libapache-jena-java'}]}]}}");

        JsonPatch.InvalidPatchException e =
                Assert.assertThrows(JsonPatch.InvalidPatchException.class, () -> patch(older, CVE_CHANGE));
        Assert.assertEquals(
                "operation 0 (add /containers/adp/0/affected/1/platforms/1): Array index 1 is out of bounds",
                e.getMessage());
    }
}
