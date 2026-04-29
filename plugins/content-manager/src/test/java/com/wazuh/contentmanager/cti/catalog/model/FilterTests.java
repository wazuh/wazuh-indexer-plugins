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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;

/** Unit tests for {@link Filter}. */
public class FilterTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // spotless:off
    private static final String FILTER_PAYLOAD = """
        {
          "document": {
            "id": "test-filter-1",
            "name": "filter/prefilter/0",
            "enabled": true,
            "metadata": {
              "title": "Test Filter",
              "author": {"name": "Wazuh"}
            },
            "check": "$host.os.platform == 'ubuntu'",
            "type": "pre-filter"
          },
          "space": {"name": "draft"}
        }
        """;
    // spotless:on

    public void testFromPayload_populatesYamlField() throws IOException {
        JsonNode payload = MAPPER.readTree(FILTER_PAYLOAD);
        Filter filter = Filter.fromPayload(payload);
        assertNotNull("yaml field should be populated", filter.getYaml());
        assertFalse("yaml field should not be empty", filter.getYaml().isEmpty());
    }

    public void testFromPayload_yamlContainsDocumentFields() throws IOException {
        JsonNode payload = MAPPER.readTree(FILTER_PAYLOAD);
        Filter filter = Filter.fromPayload(payload);
        String yaml = filter.getYaml();
        assertNotNull(yaml);
        assertTrue("YAML should contain 'check'", yaml.contains("check"));
    }

    public void testFromPayload_noDocument_yamlIsNull() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("name", "test");
        Filter filter = Filter.fromPayload(payload);
        assertNull("yaml should be null when document is absent", filter.getYaml());
    }

    public void testFromPayload_populatesDocumentField() throws IOException {
        JsonNode payload = MAPPER.readTree(FILTER_PAYLOAD);
        Filter filter = Filter.fromPayload(payload);
        assertNotNull("document field should be populated", filter.getDocument());
    }

    public void testFromPayload_populatesHashField() throws IOException {
        JsonNode payload = MAPPER.readTree(FILTER_PAYLOAD);
        Filter filter = Filter.fromPayload(payload);
        assertNotNull("hash field should be populated", filter.getHash());
        assertFalse("hash sha256 should not be empty", filter.getHash().get("sha256").isEmpty());
    }
}
