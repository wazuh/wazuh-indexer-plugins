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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;

import java.util.Map;

import com.wazuh.contentmanager.utils.Constants;

/** Unit tests for {@link Resource}'s timestamp-generation helpers. */
public class ResourceTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String GENERATED_TIMESTAMP = "2026-01-01T00:00:00Z";

    public void testSetCreationTime_generatesWhenAbsent() {
        ObjectNode resourceNode = MAPPER.createObjectNode();
        Resource.setCreationTime(resourceNode, GENERATED_TIMESTAMP);
        assertEquals(
                GENERATED_TIMESTAMP,
                resourceNode.get(Constants.KEY_METADATA).get(Constants.KEY_DATE).asText());
    }

    public void testSetCreationTime_preservesCallerSuppliedValue() {
        ObjectNode resourceNode = MAPPER.createObjectNode();
        ObjectNode metadata = resourceNode.putObject(Constants.KEY_METADATA);
        String callerDate = "2020-05-17T10:00:00Z";
        metadata.put(Constants.KEY_DATE, callerDate);

        Resource.setCreationTime(resourceNode, GENERATED_TIMESTAMP);

        assertEquals(callerDate, metadata.get(Constants.KEY_DATE).asText());
    }

    public void testSetCreationTime_generatesWhenCallerValueIsBlank() {
        ObjectNode resourceNode = MAPPER.createObjectNode();
        ObjectNode metadata = resourceNode.putObject(Constants.KEY_METADATA);
        metadata.put(Constants.KEY_DATE, "  ");

        Resource.setCreationTime(resourceNode, GENERATED_TIMESTAMP);

        assertEquals(GENERATED_TIMESTAMP, metadata.get(Constants.KEY_DATE).asText());
    }

    public void testSetLastModificationTime_generatesWhenAbsent() {
        ObjectNode resourceNode = MAPPER.createObjectNode();
        Resource.setLastModificationTime(resourceNode, GENERATED_TIMESTAMP);
        assertEquals(
                GENERATED_TIMESTAMP,
                resourceNode.get(Constants.KEY_METADATA).get(Constants.KEY_MODIFIED).asText());
    }

    public void testSetLastModificationTime_preservesCallerSuppliedValue() {
        ObjectNode resourceNode = MAPPER.createObjectNode();
        ObjectNode metadata = resourceNode.putObject(Constants.KEY_METADATA);
        String callerModified = "2021-08-09T12:30:00Z";
        metadata.put(Constants.KEY_MODIFIED, callerModified);

        Resource.setLastModificationTime(resourceNode, GENERATED_TIMESTAMP);

        assertEquals(callerModified, metadata.get(Constants.KEY_MODIFIED).asText());
    }

    public void testSetLastModificationTime_generatesWhenCallerValueIsBlank() {
        ObjectNode resourceNode = MAPPER.createObjectNode();
        ObjectNode metadata = resourceNode.putObject(Constants.KEY_METADATA);
        metadata.put(Constants.KEY_MODIFIED, "  ");

        Resource.setLastModificationTime(resourceNode, GENERATED_TIMESTAMP);

        assertEquals(GENERATED_TIMESTAMP, metadata.get(Constants.KEY_MODIFIED).asText());
    }

    /**
     * The aggregate space hash must survive a reparse. The incremental catalog-sync paths feed the
     * currently stored document back through {@code fromPayload}, so dropping it here would blank
     * {@code space.hash.sha256} on every sync and leave the space unloadable by the Engine until the
     * hash is recomputed at the end of the sync.
     */
    @SuppressWarnings("unchecked")
    public void testFromPayload_preservesExistingSpaceHash() {
        ObjectNode payload = MAPPER.createObjectNode();
        ObjectNode space = payload.putObject(Constants.KEY_SPACE);
        space.put(Constants.KEY_NAME, "standard");
        space.putObject(Constants.KEY_HASH).put(Constants.KEY_SHA256, "aggregate-hash");

        Map<String, Object> result = Resource.fromPayload(payload).getSpace();

        assertEquals("standard", result.get(Constants.KEY_NAME));
        Map<String, Object> hash = (Map<String, Object>) result.get(Constants.KEY_HASH);
        assertNotNull("space.hash should be preserved", hash);
        assertEquals("aggregate-hash", hash.get(Constants.KEY_SHA256));
    }

    /** A payload without a space hash still yields a space object holding only the name. */
    public void testFromPayload_omitsSpaceHashWhenAbsent() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.putObject(Constants.KEY_SPACE).put(Constants.KEY_NAME, "custom");

        Map<String, Object> result = Resource.fromPayload(payload).getSpace();

        assertEquals("custom", result.get(Constants.KEY_NAME));
        assertFalse("No space.hash should be invented", result.containsKey(Constants.KEY_HASH));
    }

    /** A blank hash value is treated as absent rather than persisted as an empty keyword. */
    public void testFromPayload_ignoresBlankSpaceHash() {
        ObjectNode payload = MAPPER.createObjectNode();
        ObjectNode space = payload.putObject(Constants.KEY_SPACE);
        space.put(Constants.KEY_NAME, "standard");
        space.putObject(Constants.KEY_HASH).put(Constants.KEY_SHA256, "   ");

        Map<String, Object> result = Resource.fromPayload(payload).getSpace();

        assertFalse("A blank hash should not be carried over", result.containsKey(Constants.KEY_HASH));
    }
}
