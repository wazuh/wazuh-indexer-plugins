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

/** Unit tests for {@link Kvdb}. */
public class KvdbTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    // spotless:off
    private static final String KVDB_PAYLOAD = """
        {
          "document": {
            "id": "test-kvdb-1",
            "name": "kvdb/test/0",
            "enabled": true,
            "metadata": {
              "title": "Test KVDB",
              "author": "Wazuh"
            },
            "content": {
              "key1": "value1"
            }
          },
          "space": {"name": "draft"}
        }
        """;
    // spotless:on

    public void testFromPayload_populatesYamlField() throws IOException {
        JsonNode payload = MAPPER.readTree(KVDB_PAYLOAD);
        Kvdb kvdb = Kvdb.fromPayload(payload);
        assertNotNull("yaml field should be populated", kvdb.getYaml());
        assertFalse("yaml field should not be empty", kvdb.getYaml().isEmpty());
    }

    public void testFromPayload_yamlContainsDocumentFields() throws IOException {
        JsonNode payload = MAPPER.readTree(KVDB_PAYLOAD);
        Kvdb kvdb = Kvdb.fromPayload(payload);
        String yaml = kvdb.getYaml();
        assertNotNull(yaml);
        assertTrue("YAML should contain 'title'", yaml.contains("title"));
    }

    public void testFromPayload_noDocument_yamlIsNull() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put("name", "test");
        Kvdb kvdb = Kvdb.fromPayload(payload);
        assertNull("yaml should be null when document is absent", kvdb.getYaml());
    }

    public void testFromPayload_populatesDocumentField() throws IOException {
        JsonNode payload = MAPPER.readTree(KVDB_PAYLOAD);
        Kvdb kvdb = Kvdb.fromPayload(payload);
        assertNotNull("document field should be populated", kvdb.getDocument());
    }

    public void testFromPayload_populatesHashField() throws IOException {
        JsonNode payload = MAPPER.readTree(KVDB_PAYLOAD);
        Kvdb kvdb = Kvdb.fromPayload(payload);
        assertNotNull("hash field should be populated", kvdb.getHash());
        assertFalse("hash sha256 should not be empty", kvdb.getHash().get("sha256").isEmpty());
    }
}
