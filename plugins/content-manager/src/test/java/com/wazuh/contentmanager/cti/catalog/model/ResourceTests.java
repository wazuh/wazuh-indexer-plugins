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
}
