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
package com.wazuh.contentmanager.utils;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.test.OpenSearchTestCase;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

/** Unit tests for {@link YamlUtils}. */
public class YamlUtilsTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER =
            new ObjectMapper().enable(DeserializationFeature.USE_BIG_DECIMAL_FOR_FLOATS);

    public void testFromYaml_preservesFloat() throws IOException {
        JsonNode node = YamlUtils.fromYaml("value: 5.0\n");
        assertTrue("Expected floating-point node", node.get("value").isFloatingPointNumber());
        assertEquals("5.0", node.get("value").decimalValue().toPlainString());
    }

    public void testFromYaml_preservesInteger() throws IOException {
        JsonNode node = YamlUtils.fromYaml("count: 5\n");
        assertTrue("Expected integral node", node.get("count").isIntegralNumber());
        assertEquals(5, node.get("count").asInt());
    }

    public void testToYaml_preservesFloat() throws IOException {
        JsonNode document = YamlUtils.fromYaml("version: 5.0\n");
        String yaml = YamlUtils.toYaml(document);
        assertNotNull(yaml);
        assertTrue("YAML should contain 5.0, not 5", yaml.contains("5.0"));
    }

    public void testRoundTrip_floatFidelity() throws IOException {
        JsonNode parsed = YamlUtils.fromYaml("version: 5.0\n");
        String regenerated = YamlUtils.toYaml(parsed);
        assertNotNull(regenerated);
        assertTrue("Regenerated YAML should preserve 5.0", regenerated.contains("5.0"));
    }

    public void testRoundTrip_intFidelity() throws IOException {
        JsonNode parsed = YamlUtils.fromYaml("count: 5\n");
        String regenerated = YamlUtils.toYaml(parsed);
        assertNotNull(regenerated);
        assertTrue("Regenerated YAML should contain 5", regenerated.contains("5"));
        assertFalse("Integer 5 should not be serialized as 5.0", regenerated.contains("5.0"));
    }

    public void testToYaml_withKeyOrder() throws IOException {
        JsonNode document = MAPPER.readTree("{\"b\": 2, \"a\": 1, \"c\": 3}");
        String yaml = YamlUtils.toYaml(document, Arrays.asList("a", "b"));
        assertNotNull(yaml);
        int posA = yaml.indexOf("a:");
        int posB = yaml.indexOf("b:");
        int posC = yaml.indexOf("c:");
        assertTrue("'a' should come before 'b'", posA < posB);
        assertTrue("'b' should come before 'c'", posB < posC);
    }

    public void testToYaml_withKeyOrder_unknownKeysAppendedLast() throws IOException {
        JsonNode document = MAPPER.readTree("{\"z\": 3, \"a\": 1}");
        String yaml = YamlUtils.toYaml(document, List.of("a"));
        assertNotNull(yaml);
        assertTrue("'a' should appear before 'z'", yaml.indexOf("a:") < yaml.indexOf("z:"));
    }

    public void testToYaml_nullDocument() {
        assertNull(YamlUtils.toYaml((JsonNode) null));
    }

    public void testToYaml_withKeyOrder_nullDocument() {
        assertNull(YamlUtils.toYaml(null, List.of("a", "b")));
    }

    public void testFromYaml_invalidYaml() {
        try {
            YamlUtils.fromYaml("key: [unclosed");
            fail("Expected IOException for invalid YAML");
        } catch (IOException e) {
            // expected
        }
    }

    public void testFixDecimalScale_floatGetsScale1() throws IOException {
        JsonNode node = YamlUtils.fromYaml("v: 5.0\n");
        assertTrue("Node should be floating-point", node.get("v").isFloatingPointNumber());
        assertTrue("Scale should be >= 1", node.get("v").decimalValue().scale() >= 1);
    }

    public void testFixDecimalScale_arrayElements() throws IOException {
        JsonNode node = YamlUtils.fromYaml("values:\n  - 1.0\n  - 2.0\n");
        JsonNode arr = node.get("values");
        assertTrue("Expected an array", arr.isArray());
        for (JsonNode el : arr) {
            assertTrue("Array float element scale should be >= 1", el.decimalValue().scale() >= 1);
        }
    }
}
