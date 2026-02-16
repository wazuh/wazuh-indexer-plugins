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
package com.wazuh.contentmanager.rest.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;
import org.junit.Before;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.model.Policy;

/**
 * Unit tests for the {@link Policy} class. This test suite validates Policy model operations
 * including construction, JSON serialization/deserialization, integration management, and data
 * conversions.
 *
 * <p>Tests verify the correct handling of Policy data structures, JSON transformations, and
 * business logic for managing integrations within a policy.
 */
public class PolicyTests extends OpenSearchTestCase {

    private Policy policy;
    private ObjectMapper mapper;

    /**
     * Set up the tests.
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.policy = new Policy();
        this.mapper = new ObjectMapper();
    }

    /** Test default constructor initialization. */
    public void testDefaultConstructor() {
        // Act
        Policy defaultPolicy = new Policy();

        // Assert
        Assert.assertNotNull(defaultPolicy.getIntegrations());
        Assert.assertTrue(defaultPolicy.getIntegrations().isEmpty());
        Assert.assertNull(defaultPolicy.getRootDecoder());
        Assert.assertNull(defaultPolicy.getAuthor());
        Assert.assertNull(defaultPolicy.getDescription());
        Assert.assertNull(defaultPolicy.getDocumentation());
        Assert.assertNotNull(defaultPolicy.getReferences());
        Assert.assertTrue(defaultPolicy.getReferences().isEmpty());
    }

    /** Test parameterized constructor with all fields. */
    public void testParameterizedConstructor_AllFields() {
        // Arrange
        List<String> integrations = Arrays.asList("integration1", "integration2");
        List<String> filters = List.of("filter1");
        List<String> enrichments = List.of("enrichment1");
        List<String> references = List.of("https://example.com/refs");

        // Act
        Policy testPolicy =
                new Policy(
                        "12345",
                        null, // title
                        null, // date
                        null, // modified
                        "decoder/root/0", // rootDecoder
                        integrations,
                        filters,
                        enrichments,
                        "Wazuh Inc.",
                        "Test policy description",
                        "Documentation content",
                        references);

        // Assert
        Assert.assertEquals("decoder/root/0", testPolicy.getRootDecoder());
        Assert.assertEquals(2, testPolicy.getIntegrations().size());
        Assert.assertEquals("integration1", testPolicy.getIntegrations().get(0));
        Assert.assertEquals("integration2", testPolicy.getIntegrations().get(1));
        Assert.assertEquals("Wazuh Inc.", testPolicy.getAuthor());
        Assert.assertEquals("Test policy description", testPolicy.getDescription());
        Assert.assertEquals("Documentation content", testPolicy.getDocumentation());
        Assert.assertEquals(1, testPolicy.getReferences().size());
        Assert.assertEquals("https://example.com/refs", testPolicy.getReferences().get(0));
    }

    /** Test parameterized constructor with null values. */
    public void testParameterizedConstructor_NullValues() {
        // Act
        Policy testPolicy =
                new Policy(null, null, null, null, null, null, null, null, null, null, null, null);

        // Assert
        Assert.assertNotNull(testPolicy.getIntegrations()); // Defaults to empty list
        Assert.assertTrue(testPolicy.getIntegrations().isEmpty());
        Assert.assertNull(testPolicy.getRootDecoder());
        Assert.assertNull(testPolicy.getAuthor());
        Assert.assertNotNull(testPolicy.getReferences());
        Assert.assertTrue(testPolicy.getReferences().isEmpty());
    }

    /** Test fromPayload factory method with complete payload. */
    public void testFromPayload_CompletePayload() {
        // Arrange
        ObjectNode payload = this.getPayload();

        // Act
        Policy testPolicy = Policy.fromPayload(payload);

        // Assert
        Assert.assertEquals("decoder/integrations/0", testPolicy.getRootDecoder());
        Assert.assertEquals(2, testPolicy.getIntegrations().size());
        Assert.assertEquals("integration/wazuh-core/0", testPolicy.getIntegrations().get(0));
        Assert.assertEquals("integration/wazuh-fim/0", testPolicy.getIntegrations().get(1));
        Assert.assertEquals("Wazuh Inc.", testPolicy.getAuthor());
        Assert.assertEquals("Core policy", testPolicy.getDescription());
        Assert.assertEquals("Policy documentation", testPolicy.getDocumentation());
        Assert.assertEquals(1, testPolicy.getReferences().size());
        Assert.assertEquals("https://wazuh.com", testPolicy.getReferences().get(0));
    }

    /** Helper method to create a complete JSON payload for testing. */
    private ObjectNode getPayload() {
        ObjectNode payload = this.mapper.createObjectNode();
        payload.put("root_decoder", "decoder/integrations/0");

        ArrayNode integrationsArray = this.mapper.createArrayNode();
        integrationsArray.add("integration/wazuh-core/0");
        integrationsArray.add("integration/wazuh-fim/0");
        payload.set("integrations", integrationsArray);

        payload.put("author", "Wazuh Inc.");
        payload.put("description", "Core policy");
        payload.put("documentation", "Policy documentation");
        ArrayNode referencesArray = this.mapper.createArrayNode();
        referencesArray.add("https://wazuh.com");
        payload.set("references", referencesArray);
        return payload;
    }

    /** Test fromPayload factory method with minimal payload. */
    public void testFromPayload_MinimalPayload() {
        // Arrange
        ObjectNode payload = this.mapper.createObjectNode();

        // Act
        Policy testPolicy = Policy.fromPayload(payload);

        // Assert
        Assert.assertNotNull(testPolicy);
        Assert.assertNull(testPolicy.getRootDecoder());
        Assert.assertNotNull(testPolicy.getIntegrations());
        Assert.assertTrue(testPolicy.getIntegrations().isEmpty());
    }

    /** Test fromPayload with null values in JSON. */
    public void testFromPayload_NullValues() {
        // Arrange
        ObjectNode payload = this.mapper.createObjectNode();
        payload.putNull("root_decoder");
        payload.putNull("author");

        // Act
        Policy testPolicy = Policy.fromPayload(payload);

        // Assert
        Assert.assertNull(testPolicy.getRootDecoder());
        Assert.assertNull(testPolicy.getAuthor());
    }

    /** Test fromPayload with integrations containing null elements. */
    public void testFromPayload_IntegrationsWithNulls() {
        // Arrange
        ObjectNode payload = this.mapper.createObjectNode();
        ArrayNode integrationsArray = this.mapper.createArrayNode();
        integrationsArray.add("integration1");
        integrationsArray.addNull();
        integrationsArray.add("integration2");
        payload.set("integrations", integrationsArray);

        // Act
        Policy testPolicy = Policy.fromPayload(payload);

        // Assert
        Assert.assertEquals(2, testPolicy.getIntegrations().size());
        Assert.assertEquals("integration1", testPolicy.getIntegrations().get(0));
        Assert.assertEquals("integration2", testPolicy.getIntegrations().get(1));
    }

    /** Test toMap conversion with complete policy. */
    public void testToMap_CompletePolicy() {
        // Arrange
        List<String> integrations = Arrays.asList("int1", "int2");
        this.policy.setRootDecoder("decoder/root/0");
        this.policy.setIntegrations(integrations);
        this.policy.setAuthor("Wazuh Inc.");
        this.policy.setDescription("Test description");
        this.policy.setDocumentation("Test docs");
        this.policy.setReferences(List.of("https://test.com"));

        // Act
        Map<String, Object> map = this.policy.toMap();

        // Assert
        Assert.assertEquals("decoder/root/0", map.get("root_decoder"));
        Assert.assertEquals(integrations, map.get("integrations"));
        Assert.assertEquals("Wazuh Inc.", map.get("author"));
        Assert.assertEquals("Test description", map.get("description"));
        Assert.assertEquals("Test docs", map.get("documentation"));
        Assert.assertEquals(List.of("https://test.com"), map.get("references"));
    }

    /** Test toMap conversion with minimal policy. */
    public void testToMap_MinimalPolicy() {
        // Arrange
        Policy minimalPolicy = new Policy();

        // Act
        Map<String, Object> map = minimalPolicy.toMap();

        // Assert
        Assert.assertFalse(map.containsKey("root_decoder"));
        Assert.assertFalse(map.containsKey("integrations")); // Empty list not included
        Assert.assertFalse(map.containsKey("author"));
    }

    /** Test toJson conversion with complete policy. */
    public void testToJson_CompletePolicy() {
        // Arrange
        List<String> integrations = Arrays.asList("int1", "int2");
        this.policy.setRootDecoder("decoder/root/0");
        this.policy.setIntegrations(integrations);
        this.policy.setAuthor("Wazuh Inc.");
        this.policy.setDescription("Test description");

        // Act
        ObjectNode json = this.policy.toJson();

        // Assert
        Assert.assertEquals("decoder/root/0", json.get("root_decoder").asText());
        Assert.assertTrue(json.get("integrations").isArray());
        Assert.assertEquals(2, json.get("integrations").size());
        Assert.assertEquals("int1", json.get("integrations").get(0).asText());
        Assert.assertEquals("int2", json.get("integrations").get(1).asText());
        Assert.assertEquals("Wazuh Inc.", json.get("author").asText());
        Assert.assertEquals("Test description", json.get("description").asText());
    }

    /** Test toJson conversion with empty integrations after setting to null. */
    public void testToJson_NullIntegrations() {
        // Arrange
        this.policy.setIntegrations(null); // Will be converted to empty list

        // Act
        ObjectNode json = this.policy.toJson();

        // Assert
        // Empty list creates an empty array in JSON
        Assert.assertFalse(json.has("integrations"));
    }

    /** Test addIntegration with valid integration ID. */
    public void testAddIntegration_ValidId() {
        // Act
        this.policy.addIntegration("integration1");
        this.policy.addIntegration("integration2");

        // Assert
        Assert.assertEquals(2, this.policy.getIntegrations().size());
        Assert.assertTrue(this.policy.getIntegrations().contains("integration1"));
        Assert.assertTrue(this.policy.getIntegrations().contains("integration2"));
    }

    /** Test addIntegration with duplicate integration ID. */
    public void testAddIntegration_DuplicateId() {
        // Act
        this.policy.addIntegration("integration1");
        this.policy.addIntegration("integration1"); // Duplicate

        // Assert
        Assert.assertEquals(1, this.policy.getIntegrations().size());
        Assert.assertEquals("integration1", this.policy.getIntegrations().get(0));
    }

    /** Test addIntegration with null integration ID. */
    public void testAddIntegration_NullId() {
        // Arrange
        int initialSize = this.policy.getIntegrations().size();

        // Act
        this.policy.addIntegration(null);

        // Assert
        Assert.assertEquals(initialSize, this.policy.getIntegrations().size());
    }

    /** Test removeIntegration with existing integration. */
    public void testRemoveIntegration_ExistingId() {
        // Arrange
        this.policy.addIntegration("integration1");
        this.policy.addIntegration("integration2");

        // Act
        boolean removed = this.policy.removeIntegration("integration1");

        // Assert
        Assert.assertTrue(removed);
        Assert.assertEquals(1, this.policy.getIntegrations().size());
        Assert.assertFalse(this.policy.getIntegrations().contains("integration1"));
        Assert.assertTrue(this.policy.getIntegrations().contains("integration2"));
    }

    /** Test removeIntegration with non-existing integration. */
    public void testRemoveIntegration_NonExistingId() {
        // Arrange
        this.policy.addIntegration("integration1");

        // Act
        boolean removed = this.policy.removeIntegration("integration2");

        // Assert
        Assert.assertFalse(removed);
        Assert.assertEquals(1, this.policy.getIntegrations().size());
    }

    /** Test setIntegrations with null list. */
    public void testSetIntegrations_NullList() {
        // Act
        this.policy.setIntegrations(null);

        // Assert
        Assert.assertNotNull(this.policy.getIntegrations());
        Assert.assertTrue(this.policy.getIntegrations().isEmpty());
    }

    /** Test setIntegrations with valid list. */
    public void testSetIntegrations_ValidList() {
        // Arrange
        List<String> integrations = Arrays.asList("int1", "int2", "int3");

        // Act
        this.policy.setIntegrations(integrations);

        // Assert
        Assert.assertEquals(3, this.policy.getIntegrations().size());
        Assert.assertEquals("int1", this.policy.getIntegrations().get(0));
    }

    /** Test all getters and setters. */
    public void testGettersAndSetters() {
        // Root Decoder
        this.policy.setRootDecoder("decoder/test/0");
        Assert.assertEquals("decoder/test/0", this.policy.getRootDecoder());

        // Author
        this.policy.setAuthor("Test Author");
        Assert.assertEquals("Test Author", this.policy.getAuthor());

        // Description
        this.policy.setDescription("Test Description");
        Assert.assertEquals("Test Description", this.policy.getDescription());

        // Documentation
        this.policy.setDocumentation("Test Documentation");
        Assert.assertEquals("Test Documentation", this.policy.getDocumentation());

        // References
        this.policy.setReferences(List.of("https://references.com"));
        Assert.assertEquals(1, this.policy.getReferences().size());
        Assert.assertEquals("https://references.com", this.policy.getReferences().get(0));
    }

    /** Test round-trip conversion: toJson -> fromPayload. */
    public void testRoundTrip_JsonConversion() {
        // Arrange
        List<String> integrations = Arrays.asList("int1", "int2");
        this.policy.setRootDecoder("decoder/root/0");
        this.policy.setIntegrations(integrations);
        this.policy.setAuthor("Wazuh Inc.");
        this.policy.setDescription("Test description");

        // Act
        ObjectNode json = this.policy.toJson();
        Policy reconstructed = Policy.fromPayload(json);

        // Assert
        Assert.assertEquals(this.policy.getRootDecoder(), reconstructed.getRootDecoder());
        Assert.assertEquals(
                this.policy.getIntegrations().size(), reconstructed.getIntegrations().size());
        Assert.assertEquals(this.policy.getAuthor(), reconstructed.getAuthor());
        Assert.assertEquals(this.policy.getDescription(), reconstructed.getDescription());
    }
}
