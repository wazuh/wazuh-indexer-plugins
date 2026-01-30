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

import com.google.gson.JsonArray;
import com.google.gson.JsonObject;
import org.opensearch.test.OpenSearchTestCase;
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
    }

    /** Test default constructor initialization. */
    public void testDefaultConstructor() {
        // Act
        Policy defaultPolicy = new Policy();

        // Assert
        assertEquals("policy", defaultPolicy.getType());
        assertNotNull(defaultPolicy.getIntegrations());
        assertTrue(defaultPolicy.getIntegrations().isEmpty());
        assertNull(defaultPolicy.getRootDecoder());
        assertNull(defaultPolicy.getAuthor());
        assertNull(defaultPolicy.getDescription());
        assertNull(defaultPolicy.getDocumentation());
        assertNotNull(defaultPolicy.getReferences());
        assertTrue(defaultPolicy.getReferences().isEmpty());
    }

    /** Test parameterized constructor with all fields. */
    public void testParameterizedConstructor_AllFields() {
        // Arrange
        List<String> integrations = Arrays.asList("integration1", "integration2");
        List<String> references = Arrays.asList("https://example.com/refs");

        // Act
        Policy testPolicy =
                new Policy(
                        "policy", // type
                        null, // title
                        null, // date
                        null, // modified
                        "decoder/root/0", // rootDecoder
                        integrations,
                        "Wazuh Inc.",
                        "Test policy description",
                        "Documentation content",
                        references);

        // Assert
        assertEquals("policy", testPolicy.getType());
        assertEquals("decoder/root/0", testPolicy.getRootDecoder());
        assertEquals(2, testPolicy.getIntegrations().size());
        assertEquals("integration1", testPolicy.getIntegrations().get(0));
        assertEquals("integration2", testPolicy.getIntegrations().get(1));
        assertEquals("Wazuh Inc.", testPolicy.getAuthor());
        assertEquals("Test policy description", testPolicy.getDescription());
        assertEquals("Documentation content", testPolicy.getDocumentation());
        assertEquals(1, testPolicy.getReferences().size());
        assertEquals("https://example.com/refs", testPolicy.getReferences().get(0));
    }

    /** Test parameterized constructor with null values. */
    public void testParameterizedConstructor_NullValues() {
        // Act
        Policy testPolicy = new Policy(null, null, null, null, null, null, null, null, null, null);

        // Assert
        assertEquals("policy", testPolicy.getType()); // Defaults to "policy"
        assertNotNull(testPolicy.getIntegrations()); // Defaults to empty list
        assertTrue(testPolicy.getIntegrations().isEmpty());
        assertNull(testPolicy.getRootDecoder());
        assertNull(testPolicy.getAuthor());
        assertNotNull(testPolicy.getReferences());
        assertTrue(testPolicy.getReferences().isEmpty());
    }

    /** Test fromPayload factory method with complete payload. */
    public void testFromPayload_CompletePayload() {
        // Arrange
        JsonObject payload = getPayload();

        // Act
        Policy testPolicy = Policy.fromPayload(payload);

        // Assert
        assertEquals("policy", testPolicy.getType());
        assertEquals("decoder/integrations/0", testPolicy.getRootDecoder());
        assertEquals(2, testPolicy.getIntegrations().size());
        assertEquals("integration/wazuh-core/0", testPolicy.getIntegrations().get(0));
        assertEquals("integration/wazuh-fim/0", testPolicy.getIntegrations().get(1));
        assertEquals("Wazuh Inc.", testPolicy.getAuthor());
        assertEquals("Core policy", testPolicy.getDescription());
        assertEquals("Policy documentation", testPolicy.getDocumentation());
        assertEquals(1, testPolicy.getReferences().size());
        assertEquals("https://wazuh.com", testPolicy.getReferences().get(0));
    }

    /** Helper method to create a complete JSON payload for testing. */
    private static JsonObject getPayload() {
        JsonObject payload = new JsonObject();
        payload.addProperty("type", "policy");
        payload.addProperty("root_decoder", "decoder/integrations/0");

        JsonArray integrationsArray = new JsonArray();
        integrationsArray.add("integration/wazuh-core/0");
        integrationsArray.add("integration/wazuh-fim/0");
        payload.add("integrations", integrationsArray);

        payload.addProperty("author", "Wazuh Inc.");
        payload.addProperty("description", "Core policy");
        payload.addProperty("documentation", "Policy documentation");
        JsonArray referencesArray = new JsonArray();
        referencesArray.add("https://wazuh.com");
        payload.add("references", referencesArray);
        return payload;
    }

    /** Test fromPayload factory method with minimal payload. */
    public void testFromPayload_MinimalPayload() {
        // Arrange
        JsonObject payload = new JsonObject();

        // Act
        Policy testPolicy = Policy.fromPayload(payload);

        // Assert
        assertNotNull(testPolicy);
        assertEquals("policy", testPolicy.getType()); // Default constructor sets type to "policy"
        assertNull(testPolicy.getRootDecoder());
        assertNotNull(testPolicy.getIntegrations());
        assertTrue(testPolicy.getIntegrations().isEmpty());
    }

    /** Test fromPayload with null values in JSON. */
    public void testFromPayload_NullValues() {
        // Arrange
        JsonObject payload = new JsonObject();
        payload.addProperty("type", "policy");
        payload.add("root_decoder", null);
        payload.add("author", null);

        // Act
        Policy testPolicy = Policy.fromPayload(payload);

        // Assert
        assertEquals("policy", testPolicy.getType());
        assertNull(testPolicy.getRootDecoder());
        assertNull(testPolicy.getAuthor());
    }

    /** Test fromPayload with integrations containing null elements. */
    public void testFromPayload_IntegrationsWithNulls() {
        // Arrange
        JsonObject payload = new JsonObject();
        JsonArray integrationsArray = new JsonArray();
        integrationsArray.add("integration1");
        integrationsArray.add((String) null);
        integrationsArray.add("integration2");
        payload.add("integrations", integrationsArray);

        // Act
        Policy testPolicy = Policy.fromPayload(payload);

        // Assert
        assertEquals(2, testPolicy.getIntegrations().size());
        assertEquals("integration1", testPolicy.getIntegrations().get(0));
        assertEquals("integration2", testPolicy.getIntegrations().get(1));
    }

    /** Test toMap conversion with complete policy. */
    public void testToMap_CompletePolicy() {
        // Arrange
        List<String> integrations = Arrays.asList("int1", "int2");
        this.policy.setType("policy");
        this.policy.setRootDecoder("decoder/root/0");
        this.policy.setIntegrations(integrations);
        this.policy.setAuthor("Wazuh Inc.");
        this.policy.setDescription("Test description");
        this.policy.setDocumentation("Test docs");
        this.policy.setReferences(Arrays.asList("https://test.com"));

        // Act
        Map<String, Object> map = this.policy.toMap();

        // Assert
        assertEquals("policy", map.get("type"));
        assertEquals("decoder/root/0", map.get("root_decoder"));
        assertEquals(integrations, map.get("integrations"));
        assertEquals("Wazuh Inc.", map.get("author"));
        assertEquals("Test description", map.get("description"));
        assertEquals("Test docs", map.get("documentation"));
        assertEquals(Arrays.asList("https://test.com"), map.get("references"));
    }

    /** Test toMap conversion with minimal policy. */
    public void testToMap_MinimalPolicy() {
        // Arrange
        Policy minimalPolicy = new Policy();

        // Act
        Map<String, Object> map = minimalPolicy.toMap();

        // Assert
        assertEquals("policy", map.get("type"));
        assertFalse(map.containsKey("root_decoder"));
        assertFalse(map.containsKey("integrations")); // Empty list not included
        assertFalse(map.containsKey("author"));
    }

    /** Test toJson conversion with complete policy. */
    public void testToJson_CompletePolicy() {
        // Arrange
        List<String> integrations = Arrays.asList("int1", "int2");
        this.policy.setType("policy");
        this.policy.setRootDecoder("decoder/root/0");
        this.policy.setIntegrations(integrations);
        this.policy.setAuthor("Wazuh Inc.");
        this.policy.setDescription("Test description");

        // Act
        JsonObject json = this.policy.toJson();

        // Assert
        assertEquals("policy", json.get("type").getAsString());
        assertEquals("decoder/root/0", json.get("root_decoder").getAsString());
        assertTrue(json.get("integrations").isJsonArray());
        assertEquals(2, json.getAsJsonArray("integrations").size());
        assertEquals("int1", json.getAsJsonArray("integrations").get(0).getAsString());
        assertEquals("int2", json.getAsJsonArray("integrations").get(1).getAsString());
        assertEquals("Wazuh Inc.", json.get("author").getAsString());
        assertEquals("Test description", json.get("description").getAsString());
    }

    /** Test toJson conversion with empty integrations after setting to null. */
    public void testToJson_NullIntegrations() {
        // Arrange
        this.policy.setType("policy");
        this.policy.setIntegrations(null); // Will be converted to empty list

        // Act
        JsonObject json = this.policy.toJson();

        // Assert
        assertEquals("policy", json.get("type").getAsString());
        // Empty list creates an empty array in JSON
        assertTrue(json.has("integrations"));
        assertTrue(json.get("integrations").isJsonArray());
        assertEquals(0, json.getAsJsonArray("integrations").size());
    }

    /** Test addIntegration with valid integration ID. */
    public void testAddIntegration_ValidId() {
        // Act
        this.policy.addIntegration("integration1");
        this.policy.addIntegration("integration2");

        // Assert
        assertEquals(2, this.policy.getIntegrations().size());
        assertTrue(this.policy.getIntegrations().contains("integration1"));
        assertTrue(this.policy.getIntegrations().contains("integration2"));
    }

    /** Test addIntegration with duplicate integration ID. */
    public void testAddIntegration_DuplicateId() {
        // Act
        this.policy.addIntegration("integration1");
        this.policy.addIntegration("integration1"); // Duplicate

        // Assert
        assertEquals(1, this.policy.getIntegrations().size());
        assertEquals("integration1", this.policy.getIntegrations().getFirst());
    }

    /** Test addIntegration with null integration ID. */
    public void testAddIntegration_NullId() {
        // Arrange
        int initialSize = this.policy.getIntegrations().size();

        // Act
        this.policy.addIntegration(null);

        // Assert
        assertEquals(initialSize, this.policy.getIntegrations().size());
    }

    /** Test removeIntegration with existing integration. */
    public void testRemoveIntegration_ExistingId() {
        // Arrange
        this.policy.addIntegration("integration1");
        this.policy.addIntegration("integration2");

        // Act
        boolean removed = this.policy.removeIntegration("integration1");

        // Assert
        assertTrue(removed);
        assertEquals(1, this.policy.getIntegrations().size());
        assertFalse(this.policy.getIntegrations().contains("integration1"));
        assertTrue(this.policy.getIntegrations().contains("integration2"));
    }

    /** Test removeIntegration with non-existing integration. */
    public void testRemoveIntegration_NonExistingId() {
        // Arrange
        this.policy.addIntegration("integration1");

        // Act
        boolean removed = this.policy.removeIntegration("integration2");

        // Assert
        assertFalse(removed);
        assertEquals(1, this.policy.getIntegrations().size());
    }

    /** Test setIntegrations with null list. */
    public void testSetIntegrations_NullList() {
        // Act
        this.policy.setIntegrations(null);

        // Assert
        assertNotNull(this.policy.getIntegrations());
        assertTrue(this.policy.getIntegrations().isEmpty());
    }

    /** Test setIntegrations with valid list. */
    public void testSetIntegrations_ValidList() {
        // Arrange
        List<String> integrations = Arrays.asList("int1", "int2", "int3");

        // Act
        this.policy.setIntegrations(integrations);

        // Assert
        assertEquals(3, this.policy.getIntegrations().size());
        assertEquals("int1", this.policy.getIntegrations().getFirst());
    }

    /** Test all getters and setters. */
    public void testGettersAndSetters() {
        // Act & Assert - Type
        this.policy.setType("custom-type");
        assertEquals("custom-type", this.policy.getType());

        // Root Decoder
        this.policy.setRootDecoder("decoder/test/0");
        assertEquals("decoder/test/0", this.policy.getRootDecoder());

        // Author
        this.policy.setAuthor("Test Author");
        assertEquals("Test Author", this.policy.getAuthor());

        // Description
        this.policy.setDescription("Test Description");
        assertEquals("Test Description", this.policy.getDescription());

        // Documentation
        this.policy.setDocumentation("Test Documentation");
        assertEquals("Test Documentation", this.policy.getDocumentation());

        // References
        this.policy.setReferences(Arrays.asList("https://references.com"));
        assertEquals(1, this.policy.getReferences().size());
        assertEquals("https://references.com", this.policy.getReferences().get(0));
    }

    /** Test toString method. */
    public void testToString() {
        // Arrange
        this.policy.setType("policy");
        this.policy.setRootDecoder("decoder/root/0");
        this.policy.addIntegration("integration1");
        this.policy.setAuthor("Wazuh Inc.");

        // Act
        String result = this.policy.toString();

        // Assert
        assertNotNull(result);
        assertTrue(result.contains("Policy{"));
        assertTrue(result.contains("type='policy'"));
        assertTrue(result.contains("rootDecoder='decoder/root/0'"));
        assertTrue(result.contains("integrations="));
        assertTrue(result.contains("author='Wazuh Inc.'"));
    }

    /** Test round-trip conversion: toJson -> fromPayload. */
    public void testRoundTrip_JsonConversion() {
        // Arrange
        List<String> integrations = Arrays.asList("int1", "int2");
        this.policy.setType("policy");
        this.policy.setRootDecoder("decoder/root/0");
        this.policy.setIntegrations(integrations);
        this.policy.setAuthor("Wazuh Inc.");
        this.policy.setDescription("Test description");

        // Act
        JsonObject json = this.policy.toJson();
        Policy reconstructed = Policy.fromPayload(json);

        // Assert
        assertEquals(this.policy.getType(), reconstructed.getType());
        assertEquals(this.policy.getRootDecoder(), reconstructed.getRootDecoder());
        assertEquals(this.policy.getIntegrations().size(), reconstructed.getIntegrations().size());
        assertEquals(this.policy.getAuthor(), reconstructed.getAuthor());
        assertEquals(this.policy.getDescription(), reconstructed.getDescription());
    }
}
