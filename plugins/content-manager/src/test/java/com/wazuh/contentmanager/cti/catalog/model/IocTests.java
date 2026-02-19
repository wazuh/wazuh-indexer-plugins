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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;
import org.junit.Before;

import java.util.Arrays;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.model.Ioc.IocDocument;

/** Unit tests for the {@link Ioc} class. */
public class IocTests extends OpenSearchTestCase {

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
        this.mapper = new ObjectMapper();
    }

    /** Test fromPayload with a complete IoC payload matching the CTI structure. */
    public void testFromPayload_CompletePayload() {
        // Arrange
        ObjectNode payload = this.buildCompletePayload();

        // Act
        Ioc ioc = Ioc.fromPayload(payload);

        // Assert root fields
        Assert.assertNotNull(ioc);

        // Assert document fields
        Ioc.IocDocument doc = ioc.getDocument();
        Assert.assertNotNull(doc);
        Assert.assertEquals("1593452", doc.getId());
        Assert.assertEquals("89.213.174.225:3778", doc.getName());
        Assert.assertEquals("botnet_cc", doc.getSoftwareType());
        Assert.assertEquals("ip:port", doc.getType());
        Assert.assertEquals("elf.mirai", doc.getSoftwareName());
        Assert.assertEquals(Long.valueOf(100L), doc.getConfidence());
        Assert.assertEquals("2025-09-17 16:40:05 UTC", doc.getFirstSeen());
        Assert.assertNull(doc.getLastSeen());
        Assert.assertNull(doc.getReference());
        Assert.assertEquals("elfdigest", doc.getFeedName());
        Assert.assertEquals("threat-fox", doc.getProvider());

        // Assert list fields
        Assert.assertNotNull(doc.getSoftwareAlias());
        Assert.assertEquals(2, doc.getSoftwareAlias().size());
        Assert.assertEquals("ClearFake", doc.getSoftwareAlias().get(0));
        Assert.assertEquals("Katana", doc.getSoftwareAlias().get(1));

        Assert.assertNotNull(doc.getTags());
        Assert.assertEquals(1, doc.getTags().size());
        Assert.assertEquals("Mirai", doc.getTags().get(0));
    }

    /** Test that serializing an Ioc back to JSON produces the correct dot-notation keys. */
    public void testRoundTrip_SerializationPreservesDotNotation() {
        // Arrange
        ObjectNode payload = this.buildCompletePayload();

        // Act
        Ioc ioc = Ioc.fromPayload(payload);
        JsonNode serialized = this.mapper.valueToTree(ioc);

        // Assert document uses dot-notation keys
        JsonNode doc = serialized.get("document");
        Assert.assertNotNull(doc);
        Assert.assertEquals("1593452", doc.get("id").asText());
        Assert.assertEquals("botnet_cc", doc.get("software.type").asText());
        Assert.assertEquals("elf.mirai", doc.get("software.name").asText());
        Assert.assertTrue(doc.get("software.alias").isArray());
        Assert.assertEquals("elfdigest", doc.get("feed.name").asText());
        Assert.assertEquals("2025-09-17 16:40:05 UTC", doc.get("first_seen").asText());

        // Assert null fields are omitted (NON_NULL)
        Assert.assertFalse(doc.has("last_seen"));
        Assert.assertFalse(doc.has("reference"));
    }

    /** Test fromPayload with null values for optional fields. */
    public void testFromPayload_NullOptionalFields() {
        // Arrange
        ObjectNode document = this.mapper.createObjectNode();
        document.put("id", "12345");
        document.put("name", "test-ioc");
        document.put("type", "domain");
        document.putNull("last_seen");
        document.putNull("reference");
        document.putNull("feed.name");

        ObjectNode payload = this.mapper.createObjectNode();
        payload.set("document", document);
        payload.put("type", "ioc");

        // Act
        Ioc ioc = Ioc.fromPayload(payload);

        // Assert
        Assert.assertNotNull(ioc);
        Ioc.IocDocument doc = ioc.getDocument();
        Assert.assertEquals("12345", doc.getId());
        Assert.assertNull(doc.getLastSeen());
        Assert.assertNull(doc.getReference());
        Assert.assertNull(doc.getFeedName());
    }

    /** Test fromPayload with an empty document. */
    public void testFromPayload_EmptyDocument() {
        // Arrange
        ObjectNode payload = this.mapper.createObjectNode();
        payload.set("document", this.mapper.createObjectNode());
        payload.put("type", "ioc");

        // Act
        Ioc ioc = Ioc.fromPayload(payload);

        // Assert
        Assert.assertNotNull(ioc);
        Assert.assertNotNull(ioc.getDocument());
        Assert.assertNull(ioc.getDocument().getId());
        Assert.assertNull(ioc.getDocument().getName());
        Assert.assertNull(ioc.getDocument().getConfidence());
    }

    /** Test that unknown fields in the payload are silently ignored. */
    public void testFromPayload_UnknownFieldsIgnored() {
        // Arrange
        ObjectNode document = this.mapper.createObjectNode();
        document.put("id", "99999");
        document.put("name", "test-ioc");
        document.put("unknown_field", "should be ignored");
        document.put("enrichments", "also ignored");

        ObjectNode payload = this.mapper.createObjectNode();
        payload.set("document", document);
        payload.put("type", "ioc");
        payload.put("extra_root_field", "ignored too");

        // Act
        Ioc ioc = Ioc.fromPayload(payload);

        // Assert - should parse without errors and capture known fields
        Assert.assertNotNull(ioc);
        Assert.assertEquals("99999", ioc.getDocument().getId());
        Assert.assertEquals("test-ioc", ioc.getDocument().getName());
    }

    /** Test fromPayload with minimal payload (only required structure). */
    public void testFromPayload_MinimalPayload() {
        // Arrange
        ObjectNode payload = this.mapper.createObjectNode();
        payload.put("type", "ioc");

        // Act
        Ioc ioc = Ioc.fromPayload(payload);

        // Assert
        Assert.assertNotNull(ioc);
        Assert.assertNull(ioc.getDocument());
    }

    /** Test that confidence is deserialized as Long. */
    public void testFromPayload_ConfidenceAsLong() {
        // Arrange
        ObjectNode document = this.mapper.createObjectNode();
        document.put("id", "1");
        document.put("confidence", 100);

        ObjectNode payload = this.mapper.createObjectNode();
        payload.set("document", document);
        payload.put("type", "ioc");

        // Act
        Ioc ioc = Ioc.fromPayload(payload);

        // Assert
        Assert.assertEquals(Long.valueOf(100L), ioc.getDocument().getConfidence());
    }

    /** Test getters and setters for Ioc root fields. */
    public void testGettersAndSetters_RootFields() {
        // Arrange
        Ioc ioc = new Ioc();

        // Act
        ioc.setDocument(new Ioc.IocDocument());

        // Assert
        Assert.assertNotNull(ioc.getDocument());
    }

    /** Test getters and setters for IocDocument fields. */
    public void testGettersAndSetters_DocumentFields() {
        // Arrange
        IocDocument doc = getIocDocument();

        // Assert
        Assert.assertEquals("123", doc.getId());
        Assert.assertEquals("test", doc.getName());
        Assert.assertEquals("ip", doc.getType());
        Assert.assertEquals(Long.valueOf(80L), doc.getConfidence());
        Assert.assertEquals("2025-01-01", doc.getFirstSeen());
        Assert.assertEquals("2025-06-01", doc.getLastSeen());
        Assert.assertEquals("test-provider", doc.getProvider());
        Assert.assertEquals("https://example.com", doc.getReference());
        Assert.assertEquals("test-feed", doc.getFeedName());
        Assert.assertEquals("malware", doc.getSoftwareType());
        Assert.assertEquals("test-malware", doc.getSoftwareName());
        Assert.assertEquals(2, doc.getSoftwareAlias().size());
        Assert.assertEquals(1, doc.getTags().size());
    }

    private static IocDocument getIocDocument() {
        IocDocument doc = new IocDocument();

        // Act
        doc.setId("123");
        doc.setName("test");
        doc.setType("ip");
        doc.setConfidence(80L);
        doc.setFirstSeen("2025-01-01");
        doc.setLastSeen("2025-06-01");
        doc.setProvider("test-provider");
        doc.setReference("https://example.com");
        doc.setFeedName("test-feed");
        doc.setSoftwareType("malware");
        doc.setSoftwareName("test-malware");
        doc.setSoftwareAlias(Arrays.asList("alias1", "alias2"));
        doc.setTags(List.of("tag1"));
        return doc;
    }

    /**
     * Builds the complete IoC payload matching the CTI structure with flat dot-notation keys.
     *
     * @return A complete IoC ObjectNode payload.
     */
    private ObjectNode buildCompletePayload() {
        ObjectNode document = this.mapper.createObjectNode();
        document.put("id", "1593452");
        document.put("name", "89.213.174.225:3778");
        document.put("software.type", "botnet_cc");
        document.put("type", "ip:port");
        document.put("software.name", "elf.mirai");

        ArrayNode softwareAlias = this.mapper.createArrayNode();
        softwareAlias.add("ClearFake");
        softwareAlias.add("Katana");
        document.set("software.alias", softwareAlias);

        document.put("confidence", 100);
        document.put("first_seen", "2025-09-17 16:40:05 UTC");
        document.putNull("last_seen");
        document.putNull("reference");
        document.put("feed.name", "elfdigest");

        ArrayNode tags = this.mapper.createArrayNode();
        tags.add("Mirai");
        document.set("tags", tags);

        document.put("provider", "threat-fox");

        ObjectNode payload = this.mapper.createObjectNode();
        payload.set("document", document);
        payload.put("type", "ioc");

        return payload;
    }
}
