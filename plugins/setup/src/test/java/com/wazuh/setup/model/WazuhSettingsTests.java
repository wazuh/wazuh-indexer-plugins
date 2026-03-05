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
package com.wazuh.setup.model;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.test.OpenSearchTestCase;

/**
 * Unit tests for {@link WazuhSettings}. Validates parsing, serialization, and validation behavior.
 */
public class WazuhSettingsTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** Default constructor creates settings with index_raw_events=false. */
    public void testCreateDefault_hasDefaultValues() {
        WazuhSettings settings = WazuhSettings.createDefault();

        assertNotNull(settings.getEngine());
        assertEquals(Boolean.FALSE, settings.getEngine().getIndexRawEvents());
    }

    /** Parse valid JSON with index_raw_events=true. */
    public void testFromJson_validPayloadTrue() {
        String json = "{\"engine\":{\"index_raw_events\":true}}";
        WazuhSettings settings = WazuhSettings.fromJson(json);

        assertNotNull(settings);
        assertNotNull(settings.getEngine());
        assertEquals(Boolean.TRUE, settings.getEngine().getIndexRawEvents());
    }

    /** Parse valid JSON with index_raw_events=false. */
    public void testFromJson_validPayloadFalse() {
        String json = "{\"engine\":{\"index_raw_events\":false}}";
        WazuhSettings settings = WazuhSettings.fromJson(json);

        assertNotNull(settings);
        assertNotNull(settings.getEngine());
        assertEquals(Boolean.FALSE, settings.getEngine().getIndexRawEvents());
    }

    /** Parse JSON with missing engine object -> returns null (validation fails). */
    public void testFromJson_missingEngine() {
        String json = "{}";
        WazuhSettings settings = WazuhSettings.fromJson(json);

        assertNull(settings);
    }

    /** Parse JSON with engine but missing index_raw_events -> returns null (validation fails). */
    public void testFromJson_missingIndexRawEvents() {
        String json = "{\"engine\":{}}";
        WazuhSettings settings = WazuhSettings.fromJson(json);

        assertNull(settings);
    }

    /** Parse malformed JSON -> returns null. */
    public void testFromJson_invalidJson() {
        String json = "{not valid json";
        WazuhSettings settings = WazuhSettings.fromJson(json);

        assertNull(settings);
    }

    /** Parse JSON with string instead of boolean -> returns null (type validation). */
    public void testFromJson_nonBooleanValue() {
        String json = "{\"engine\":{\"index_raw_events\":\"yes\"}}";
        WazuhSettings settings = WazuhSettings.fromJson(json);

        assertNull(settings);
    }

    /** Parse null input -> returns null. */
    public void testFromJson_nullInput() {
        WazuhSettings settings = WazuhSettings.fromJson(null);
        assertNull(settings);
    }

    /** Parse empty string -> returns null. */
    public void testFromJson_emptyString() {
        WazuhSettings settings = WazuhSettings.fromJson("");
        assertNull(settings);
    }

    /** Serialization to JSON produces valid output. */
    public void testToJson_producesValidJson() {
        WazuhSettings settings = WazuhSettings.createDefault();
        String json = settings.toJson();

        assertNotNull(json);
        assertTrue(json.contains("\"engine\""));
        assertTrue(json.contains("\"index_raw_events\":false"));
    }

    /** Roundtrip: serialize then parse should produce equivalent settings. */
    public void testRoundtrip_preservesValues() {
        WazuhSettings original = WazuhSettings.createDefault();
        original.getEngine().setIndexRawEvents(true);

        String json = original.toJson();
        assertNotNull("toJson() should produce non-null JSON", json);
        assertTrue("JSON should contain engine", json.contains("engine"));
        assertTrue("JSON should contain index_raw_events", json.contains("index_raw_events"));

        WazuhSettings parsed = WazuhSettings.fromJson(json);

        assertNotNull("fromJson() should parse valid JSON: " + json, parsed);
        assertNotNull("Engine should not be null after parsing", parsed.getEngine());
        assertEquals(original.getEngine().getIndexRawEvents(), parsed.getEngine().getIndexRawEvents());
    }

    /** Engine.createDefault() creates engine with default values. */
    public void testEngine_createDefault() {
        WazuhSettings.Engine engine = WazuhSettings.Engine.createDefault();
        assertEquals(Boolean.FALSE, engine.getIndexRawEvents());
    }

    /** validate() returns null for valid payload. */
    public void testValidate_validPayload_returnsNull() throws Exception {
        JsonNode root = MAPPER.readTree("{\"engine\":{\"index_raw_events\":true}}");
        assertNull(WazuhSettings.validate(root));
    }

    /** validate() returns error for missing engine. */
    public void testValidate_missingEngine_returnsError() throws Exception {
        JsonNode root = MAPPER.readTree("{}");
        String error = WazuhSettings.validate(root);
        assertNotNull(error);
        assertTrue(error.contains("engine"));
    }

    /** validate() returns error for missing index_raw_events. */
    public void testValidate_missingIndexRawEvents_returnsError() throws Exception {
        JsonNode root = MAPPER.readTree("{\"engine\":{}}");
        String error = WazuhSettings.validate(root);
        assertNotNull(error);
        assertTrue(error.contains("engine.index_raw_events"));
    }

    /** validate() returns error for non-boolean index_raw_events. */
    public void testValidate_nonBooleanIndexRawEvents_returnsError() throws Exception {
        JsonNode root = MAPPER.readTree("{\"engine\":{\"index_raw_events\":\"yes\"}}");
        String error = WazuhSettings.validate(root);
        assertNotNull(error);
        assertTrue(error.contains("boolean"));
    }

    /** validate() returns error for null root. */
    public void testValidate_nullRoot_returnsError() {
        String error = WazuhSettings.validate(null);
        assertNotNull(error);
        assertTrue(error.contains("engine"));
    }

    /** validate() returns error for engine as non-object. */
    public void testValidate_engineNotObject_returnsError() throws Exception {
        JsonNode root = MAPPER.readTree("{\"engine\":\"not an object\"}");
        String error = WazuhSettings.validate(root);
        assertNotNull(error);
        assertTrue(error.contains("engine"));
    }
}
