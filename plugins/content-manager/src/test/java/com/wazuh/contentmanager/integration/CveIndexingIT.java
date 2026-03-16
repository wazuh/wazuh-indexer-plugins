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
package com.wazuh.contentmanager.integration;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.plugins.Plugin;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.util.Collection;
import java.util.Collections;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.catalog.model.Cve;

/**
 * Integration tests for CVE indexing with type field. Verifies that CVE documents are correctly
 * indexed with the type field set based on the resource name/dataType.
 */
@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class CveIndexingIT extends OpenSearchIntegTestCase {

    private ObjectMapper mapper;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mapper = new ObjectMapper();
        ensureGreen();
    }

    @Override
    protected Collection<Class<? extends Plugin>> nodePlugins() {
        return Collections.singletonList(ContentManagerPlugin.class);
    }

    /** Verifies that CVE documents with CVE-* resource names are indexed with type="CVE" */
    public void testIndexCveWithCveType() {
        String resourceName = "CVE-2026-0001";
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", resourceName);

        Cve cve = Cve.fromPayload(payload, resourceName);
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("CVE resource should have type field", serialized.has("type"));
        assertEquals("CVE", serialized.get("type").asText());
    }

    /** Verifies that TID documents with TID-* resource names are indexed with type="TID" */
    public void testIndexCveWithTidType() {
        String resourceName = "TID-001";
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", resourceName);

        Cve cve = Cve.fromPayload(payload, resourceName);
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("TID resource should have type field", serialized.has("type"));
        assertEquals("TID", serialized.get("type").asText());
    }

    /** Verifies that CNA-MAPPING-GLOBAL documents are indexed with correct type */
    public void testIndexCveWithCnaMappingGlobalType() {
        String resourceName = "CNA-MAPPING-GLOBAL";
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", resourceName);

        Cve cve = Cve.fromPayload(payload, resourceName);
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("CNA-MAPPING-GLOBAL resource should have type field", serialized.has("type"));
        assertEquals("CNA-MAPPING-GLOBAL", serialized.get("type").asText());
    }

    /** Verifies that FEED-GLOBAL documents are indexed with correct type */
    public void testIndexCveWithFeedGlobalType() {
        String resourceName = "FEED-GLOBAL";
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", resourceName);

        Cve cve = Cve.fromPayload(payload, resourceName);
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("FEED-GLOBAL resource should have type field", serialized.has("type"));
        assertEquals("FEED-GLOBAL", serialized.get("type").asText());
    }

    /** Verifies that OSCPE-GLOBAL documents are indexed with correct type */
    public void testIndexCveWithOscpeGlobalType() {
        String resourceName = "OSCPE-GLOBAL";
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", resourceName);

        Cve cve = Cve.fromPayload(payload, resourceName);
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("OSCPE-GLOBAL resource should have type field", serialized.has("type"));
        assertEquals("OSCPE-GLOBAL", serialized.get("type").asText());
    }

    /** Verifies that TCPE documents are indexed with correct type */
    public void testIndexCveWithTcpeType() {
        String resourceName = "TCPE";
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", resourceName);

        Cve cve = Cve.fromPayload(payload, resourceName);
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("TCPE resource should have type field", serialized.has("type"));
        assertEquals("TCPE", serialized.get("type").asText());
    }

    /** Verifies that TVENDORS documents are indexed with correct type */
    public void testIndexCveWithTvendorsType() {
        String resourceName = "TVENDORS";
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", resourceName);

        Cve cve = Cve.fromPayload(payload, resourceName);
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("TVENDORS resource should have type field", serialized.has("type"));
        assertEquals("TVENDORS", serialized.get("type").asText());
    }

    /** Verifies that offset field is preserved during serialization */
    public void testIndexCveWithOffset() {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", "CVE-2026-0002");
        payload.put("offset", 500L);

        Cve cve = Cve.fromPayload(payload, "CVE-2026-0002");
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("Should have offset field", serialized.has("offset"));
        assertEquals(500L, serialized.get("offset").asLong());
        assertTrue("Should have type field", serialized.has("type"));
        assertEquals("CVE", serialized.get("type").asText());
    }

    /** Verifies that Cve serialization includes all required fields */
    public void testIndexCveSerializationIncludesAllFields() {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", "CVE-2026-0001");
        payload.put("offset", 999L);

        Cve cve = Cve.fromPayload(payload, "CVE-2026-0001");
        JsonNode serialized = mapper.valueToTree(cve);

        assertTrue("Should have document field", serialized.has("document"));
        assertTrue("Should have offset field", serialized.has("offset"));
        assertTrue("Should have type field", serialized.has("type"));
        assertEquals("CVE", serialized.get("type").asText());
        assertEquals(999L, serialized.get("offset").asLong());
    }

    /** Verifies that documents without a resource name do not have a type field */
    public void testIndexCveWithoutType() {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("id", "UNKNOWN-001");

        Cve cve = Cve.fromPayload(payload, "UNKNOWN-RESOURCE");
        JsonNode serialized = mapper.valueToTree(cve);

        assertFalse("Unknown resource should not have type field", serialized.has("type"));
    }

    /** Verifies that case variations in resource names are normalized to correct type */
    public void testIndexCveWithCaseVariations() {
        // Test lowercase
        Cve cve1 = Cve.fromPayload(mapper.createObjectNode(), "cve-2026-0001");
        JsonNode serialized1 = mapper.valueToTree(cve1);
        assertEquals(
                "Lowercase CVE pattern should map to CVE type", "CVE", serialized1.get("type").asText());

        // Test uppercase
        Cve cve2 = Cve.fromPayload(mapper.createObjectNode(), "CVE-2026-0002");
        JsonNode serialized2 = mapper.valueToTree(cve2);
        assertEquals(
                "Uppercase CVE pattern should map to CVE type", "CVE", serialized2.get("type").asText());

        // Test mixed case
        Cve cve3 = Cve.fromPayload(mapper.createObjectNode(), "Cve-2026-0003");
        JsonNode serialized3 = mapper.valueToTree(cve3);
        assertEquals(
                "Mixed case CVE pattern should map to CVE type", "CVE", serialized3.get("type").asText());
    }

    /** Verifies that all CVE types are correctly derived and stored */
    public void testIndexCveAllTypes() {
        String[] resources = {
            "CNA-MAPPING-GLOBAL",
            "CVE-2026-0001",
            "FEED-GLOBAL",
            "OSCPE-GLOBAL",
            "TCPE",
            "TID-001",
            "TVENDORS"
        };
        String[] expectedTypes = {
            "CNA-MAPPING-GLOBAL", "CVE", "FEED-GLOBAL", "OSCPE-GLOBAL", "TCPE", "TID", "TVENDORS"
        };

        for (int i = 0; i < resources.length; i++) {
            Cve cve = Cve.fromPayload(mapper.createObjectNode(), resources[i]);
            JsonNode serialized = mapper.valueToTree(cve);
            assertEquals(
                    "Type for resource " + resources[i], expectedTypes[i], serialized.get("type").asText());
        }
    }

    /** Verifies that explicit type in payload takes precedence over derived type */
    public void testIndexCveExplicitTypeOverridesDerived() {
        ObjectNode payload = mapper.createObjectNode();
        payload.put("type", "TCPE");

        Cve cve = Cve.fromPayload(payload, "CVE-2026-0001");
        JsonNode serialized = mapper.valueToTree(cve);

        assertEquals(
                "Explicit type should override derived type", "TCPE", serialized.get("type").asText());
    }
}
