/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.rest.services.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.exc.ValueInstantiationException;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.util.Collections;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.rest.model.SpaceDiff;

@SuppressWarnings("UnqualifiedStaticUsage")
public class SpaceDiffTests extends OpenSearchTestCase {

    private ObjectMapper objectMapper;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.objectMapper = new ObjectMapper();
    }

    public void testSpaceDiff() throws Exception {
        // spotless:off
        String payload = """
                {
                  "space": "draft",
                  "changes": {
                    "policy": [],
                    "integrations": [{"operation": "remove", "id": "12345"}],
                    "kvdbs": [{"operation": "update", "id": "12345"}],
                    "decoders": [{"operation": "add", "id": "12345"}],
                    "filters": []
                  }
                }
                """;
        // spotless:on

        // Parse into model using Jackson
        SpaceDiff spaceDiff = this.objectMapper.readValue(payload, SpaceDiff.class);

        // Ensure fields are correctly parsed
        assertNotNull(spaceDiff);
        assertEquals(Space.DRAFT, spaceDiff.getSpace());
        assertNotNull(spaceDiff.getChanges());

        // Verify policy is empty
        assertNotNull(spaceDiff.getChanges().getPolicy());
        assertTrue(spaceDiff.getChanges().getPolicy().isEmpty());

        // Verify integrations
        assertNotNull(spaceDiff.getChanges().getIntegrations());
        assertEquals(1, spaceDiff.getChanges().getIntegrations().size());
        assertEquals(
                SpaceDiff.Operation.REMOVE,
                spaceDiff.getChanges().getIntegrations().getFirst().getOperation());
        assertEquals("12345", spaceDiff.getChanges().getIntegrations().getFirst().getId());

        // Verify kvdbs
        assertNotNull(spaceDiff.getChanges().getKvdbs());
        assertEquals(1, spaceDiff.getChanges().getKvdbs().size());
        assertEquals(
                SpaceDiff.Operation.UPDATE, spaceDiff.getChanges().getKvdbs().getFirst().getOperation());
        assertEquals("12345", spaceDiff.getChanges().getKvdbs().getFirst().getId());

        // Verify decoders
        assertNotNull(spaceDiff.getChanges().getDecoders());
        assertEquals(1, spaceDiff.getChanges().getDecoders().size());
        assertEquals(
                SpaceDiff.Operation.ADD, spaceDiff.getChanges().getDecoders().getFirst().getOperation());
        assertEquals("12345", spaceDiff.getChanges().getDecoders().getFirst().getId());

        // Verify filters is empty
        assertNotNull(spaceDiff.getChanges().getFilters());
        assertTrue(spaceDiff.getChanges().getFilters().isEmpty());
    }

    public void testSpaceDiffWithTestSpace() throws Exception {
        // spotless:off
        String payload = """
                {
                  "space": "test",
                  "changes": {
                    "policy": [{"operation": "update", "id": "policy-1"}],
                    "integrations": [],
                    "kvdbs": [],
                    "decoders": [],
                    "filters": []
                  }
                }
                """;
        // spotless:on

        SpaceDiff spaceDiff = this.objectMapper.readValue(payload, SpaceDiff.class);

        assertNotNull(spaceDiff);
        assertEquals(Space.TEST, spaceDiff.getSpace());
        assertNotNull(spaceDiff.getChanges().getPolicy());
        assertEquals(1, spaceDiff.getChanges().getPolicy().size());
        assertEquals(
                SpaceDiff.Operation.UPDATE, spaceDiff.getChanges().getPolicy().getFirst().getOperation());
        assertEquals("policy-1", spaceDiff.getChanges().getPolicy().getFirst().getId());
    }

    public void testSpaceDiffWithMultipleOperations() throws Exception {
        // spotless:off
        String payload = """
                {
                  "space": "draft",
                  "changes": {
                    "policy": [],
                    "integrations": [],
                    "kvdbs": [],
                    "decoders": [
                      {"operation": "add", "id": "decoder-1"},
                      {"operation": "update", "id": "decoder-2"},
                      {"operation": "remove", "id": "decoder-3"}
                    ],
                    "filters": [
                      {"operation": "add", "id": "filter-1"}
                    ]
                  }
                }
                """;
        // spotless:on

        SpaceDiff spaceDiff = this.objectMapper.readValue(payload, SpaceDiff.class);

        assertNotNull(spaceDiff);
        assertEquals(Space.DRAFT, spaceDiff.getSpace());

        // Verify multiple decoders operations
        assertEquals(3, spaceDiff.getChanges().getDecoders().size());
        assertEquals(
                SpaceDiff.Operation.ADD, spaceDiff.getChanges().getDecoders().getFirst().getOperation());
        assertEquals("decoder-1", spaceDiff.getChanges().getDecoders().getFirst().getId());
        assertEquals(
                SpaceDiff.Operation.UPDATE, spaceDiff.getChanges().getDecoders().get(1).getOperation());
        assertEquals("decoder-2", spaceDiff.getChanges().getDecoders().get(1).getId());
        assertEquals(
                SpaceDiff.Operation.REMOVE, spaceDiff.getChanges().getDecoders().get(2).getOperation());
        assertEquals("decoder-3", spaceDiff.getChanges().getDecoders().get(2).getId());

        // Verify filters
        assertEquals(1, spaceDiff.getChanges().getFilters().size());
        assertEquals(
                SpaceDiff.Operation.ADD, spaceDiff.getChanges().getFilters().getFirst().getOperation());
        assertEquals("filter-1", spaceDiff.getChanges().getFilters().getFirst().getId());
    }

    public void testSpaceDiffSerialization() throws Exception {
        // Create SpaceDiff object
        SpaceDiff spaceDiff = new SpaceDiff();
        spaceDiff.setSpace(Space.DRAFT);

        SpaceDiff.Changes changes = new SpaceDiff.Changes();
        changes.setPolicy(Collections.emptyList());
        changes.setIntegrations(Collections.emptyList());
        changes.setKvdbs(Collections.emptyList());
        changes.setFilters(Collections.emptyList());

        SpaceDiff.OperationItem decoder = new SpaceDiff.OperationItem();
        decoder.setOperation(SpaceDiff.Operation.ADD);
        decoder.setId("decoder-123");
        changes.setDecoders(List.of(decoder));

        spaceDiff.setChanges(changes);

        // Serialize to JSON
        String json = this.objectMapper.writeValueAsString(spaceDiff);

        // Verify JSON contains expected values
        assertTrue(json.contains("\"space\":\"draft\""));
        assertTrue(json.contains("\"operation\":\"add\""));
        assertTrue(json.contains("\"id\":\"decoder-123\""));

        // Deserialize back and verify
        SpaceDiff deserialized = this.objectMapper.readValue(json, SpaceDiff.class);
        assertEquals(Space.DRAFT, deserialized.getSpace());
        assertEquals(1, deserialized.getChanges().getDecoders().size());
        assertEquals(
                SpaceDiff.Operation.ADD, deserialized.getChanges().getDecoders().getFirst().getOperation());
        assertEquals("decoder-123", deserialized.getChanges().getDecoders().getFirst().getId());
    }

    public void testOperationEnumCaseInsensitive() throws Exception {
        // spotless:off
        String payload = """
                {
                  "space": "draft",
                  "changes": {
                    "policy": [],
                    "integrations": [{"operation": "REMOVE", "id": "1"}],
                    "kvdbs": [{"operation": "Update", "id": "2"}],
                    "decoders": [{"operation": "AdD", "id": "3"}],
                    "filters": []
                  }
                }
                """;
        // spotless:on

        SpaceDiff spaceDiff = this.objectMapper.readValue(payload, SpaceDiff.class);

        assertNotNull(spaceDiff);
        assertEquals(
                SpaceDiff.Operation.REMOVE,
                spaceDiff.getChanges().getIntegrations().getFirst().getOperation());
        assertEquals(
                SpaceDiff.Operation.UPDATE, spaceDiff.getChanges().getKvdbs().getFirst().getOperation());
        assertEquals(
                SpaceDiff.Operation.ADD, spaceDiff.getChanges().getDecoders().getFirst().getOperation());
    }

    public void testInvalidOperationThrowsException() {
        // spotless:off
        String payload = """
                {
                  "space": "draft",
                  "changes": {
                    "policy": [],
                    "integrations": [{"operation": "invalid", "id": "1"}],
                    "kvdbs": [],
                    "decoders": [],
                    "filters": []
                  }
                }
                """;
        // spotless:on

        Exception exception =
                assertThrows(
                        Exception.class,
                        () -> {
                            this.objectMapper.readValue(payload, SpaceDiff.class);
                        });

        assertTrue(exception.getMessage().contains("Unknown operation"));
    }

    public void testInvalidSpaceThrowsException() {
        // spotless:off
        String payload = """
                {
                  "space": "invalid",
                  "changes": {
                    "policy": [],
                    "integrations": [],
                    "kvdbs": [],
                    "decoders": [],
                    "filters": []
                  }
                }
                """;
        // spotless:on

        Exception exception =
                assertThrows(
                        ValueInstantiationException.class,
                        () -> this.objectMapper.readValue(payload, SpaceDiff.class));

        assertTrue(exception.getMessage().contains("Unknown space: [invalid]."));
    }
}
