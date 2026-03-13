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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;

/** Unit tests for {@link Cve}. */
public class CveTests extends OpenSearchTestCase {

    private ObjectMapper mapper;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.mapper = new ObjectMapper();
    }

    /** Verifies raw CVE payloads are normalized under the `document` field. */
    public void testFromPayload_RawPayloadSerializedAsDocument() {
        ObjectNode rawPayload = this.mapper.createObjectNode();
        rawPayload.put("dataType", "CVE_RECORD");
        ObjectNode metadata = this.mapper.createObjectNode();
        metadata.put("cveId", "CVE-2026-0001");
        rawPayload.set("cveMetadata", metadata);
        rawPayload.put("offset", 10L);

        Cve cve = Cve.fromPayload(rawPayload, "CVE-2026-0001");
        JsonNode serialized = this.mapper.valueToTree(cve);

        assertTrue(serialized.has("document"));
        assertFalse(serialized.has("payload"));
        assertEquals(
                "CVE-2026-0001", serialized.get("document").get("cveMetadata").get("cveId").asText());
        assertEquals(10L, serialized.get("offset").asLong());
        assertEquals("CVE", serialized.get("type").asText());
        assertFalse(serialized.get("document").has("offset"));
    }

    /** Verifies already wrapped `document` payloads are preserved. */
    public void testFromPayload_DocumentWrapperIsPreserved() {
        ObjectNode wrapped = this.mapper.createObjectNode();
        ObjectNode document = this.mapper.createObjectNode();
        document.put("dataType", "CVE_RECORD");
        document.put("dataVersion", "5.1");
        wrapped.set("document", document);

        Cve cve = Cve.fromPayload(wrapped, "CVE-2026-0002");
        JsonNode serialized = this.mapper.valueToTree(cve);

        assertEquals("5.1", serialized.get("document").get("dataVersion").asText());
        assertEquals("CVE", serialized.get("type").asText());
        assertFalse(serialized.has("payload"));
    }

    /** Verifies legacy payload-wrapped CVEs are still accepted for backward compatibility. */
    public void testFromPayload_LegacyPayloadWrapperSupported() {
        ObjectNode wrapped = this.mapper.createObjectNode();
        ObjectNode legacyPayload = this.mapper.createObjectNode();
        legacyPayload.put("dataType", "CVE_RECORD");
        wrapped.set("payload", legacyPayload);

        Cve cve = Cve.fromPayload(wrapped, "CVE-2026-0003");
        JsonNode serialized = this.mapper.valueToTree(cve);

        assertTrue(serialized.has("document"));
        assertEquals("CVE_RECORD", serialized.get("document").get("dataType").asText());
        assertEquals("CVE", serialized.get("type").asText());
        assertFalse(serialized.has("payload"));
    }

    /** Verifies unknown resource names do not force a top-level content type. */
    public void testFromPayload_UnknownResourceDoesNotSetType() {
        ObjectNode rawPayload = this.mapper.createObjectNode();
        rawPayload.put("dataType", "UNKNOWN_TYPE");

        Cve cve = Cve.fromPayload(rawPayload, "UNKNOWN-RESOURCE");
        JsonNode serialized = this.mapper.valueToTree(cve);

        assertTrue(serialized.has("document"));
        assertFalse(serialized.has("type"));
    }

    /** Verifies deriveType supports all expected resource patterns. */
    public void testDeriveType_FromResourcePatterns() {
        assertEquals("CNA-MAPPING-GLOBAL", Cve.deriveType("CNA-MAPPING-GLOBAL"));
        assertEquals("CVE", Cve.deriveType("CVE-2026-0001"));
        assertEquals("FEED-GLOBAL", Cve.deriveType("FEED-GLOBAL"));
        assertEquals("OSCPE-GLOBAL", Cve.deriveType("OSCPE-GLOBAL"));
        assertEquals("TCPE", Cve.deriveType("TCPE"));
        assertEquals("TID", Cve.deriveType("TID-001"));
        assertEquals("TVENDORS", Cve.deriveType("TVENDORS"));
        assertNull(Cve.deriveType("UNMAPPED"));
    }
}
