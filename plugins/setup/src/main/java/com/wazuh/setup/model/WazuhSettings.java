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

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import com.wazuh.setup.index.SettingsIndex;

/**
 * Model representing Wazuh Settings stored in the {@code .wazuh-settings} index.
 *
 * <p>This class serves as the root container for all Wazuh configuration settings. Currently
 * supports Engine settings, with the structure designed to accommodate additional setting
 * categories in the future (e.g., cluster settings, security settings).
 *
 * <p>Example JSON structure:
 *
 * <pre>{@code
 * {
 *   "engine": {
 *     "index_raw_events": false
 *   }
 * }
 * }</pre>
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public class WazuhSettings {
    private static final ObjectMapper MAPPER =
            new ObjectMapper().configure(DeserializationFeature.FAIL_ON_NULL_FOR_PRIMITIVES, true);

    /** JSON key for the engine settings object. */
    public static final String KEY_ENGINE = "engine";

    /** JSON key for the index_raw_events field within engine settings. */
    public static final String KEY_INDEX_RAW_EVENTS = "index_raw_events";

    /** Default value for index_raw_events when not specified. */
    public static final boolean DEFAULT_INDEX_RAW_EVENTS = false;

    @JsonProperty(KEY_ENGINE)
    private Engine engine;

    /** Default constructor for Jackson deserialization. Does not set defaults. */
    public WazuhSettings() {}

    /**
     * Constructs a WazuhSettings instance with the specified Engine settings.
     *
     * @param engine The Engine settings.
     */
    @JsonCreator
    public WazuhSettings(@JsonProperty(KEY_ENGINE) Engine engine) {
        this.engine = engine;
    }

    /**
     * Creates a WazuhSettings instance with default values.
     *
     * @return A new WazuhSettings instance with default settings.
     */
    public static WazuhSettings createDefault() {
        WazuhSettings settings = new WazuhSettings();
        settings.engine = Engine.createDefault();
        return settings;
    }

    /**
     * Parses a WazuhSettings instance from a JSON payload.
     *
     * @param payload The JSON node containing the settings.
     * @return A WazuhSettings instance, or null if parsing fails.
     */
    public static WazuhSettings fromPayload(JsonNode payload) {
        if (payload == null) {
            return null;
        }
        try {
            return MAPPER.treeToValue(payload, WazuhSettings.class);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    /**
     * Parses a WazuhSettings instance from a JSON string.
     *
     * @param json The JSON string containing the settings.
     * @return A WazuhSettings instance, or null if parsing fails.
     */
    public static WazuhSettings fromJson(String json) {
        if (json == null || json.isEmpty()) {
            return null;
        }
        try {
            JsonNode root = MAPPER.readTree(json);
            String validationError = validate(root);
            if (validationError != null) {
                return null;
            }
            return MAPPER.treeToValue(root, WazuhSettings.class);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Validates the JSON payload structure before parsing. Checks that required fields exist and have
     * correct types.
     *
     * @param root The JSON root node to validate.
     * @return null if valid, error message string if invalid.
     */
    public static String validate(JsonNode root) {
        if (root == null || !root.isObject()) {
            return String.format(SettingsIndex.E_400_MISSING_FIELD, KEY_ENGINE);
        }

        // Validate: engine object must exist
        if (!root.has(KEY_ENGINE) || !root.get(KEY_ENGINE).isObject()) {
            return String.format(SettingsIndex.E_400_MISSING_FIELD, KEY_ENGINE);
        }

        // Validate: engine.index_raw_events must be boolean
        JsonNode engineNode = root.get(KEY_ENGINE);
        if (!engineNode.has(KEY_INDEX_RAW_EVENTS)) {
            return String.format(
                    SettingsIndex.E_400_MISSING_FIELD, KEY_ENGINE + "." + KEY_INDEX_RAW_EVENTS);
        }
        if (!engineNode.get(KEY_INDEX_RAW_EVENTS).isBoolean()) {
            return String.format(
                    SettingsIndex.E_400_INVALID_TYPE, KEY_ENGINE + "." + KEY_INDEX_RAW_EVENTS, "boolean");
        }

        return null;
    }

    /**
     * Gets the Engine settings.
     *
     * @return The Engine settings.
     */
    public Engine getEngine() {
        return this.engine;
    }

    /**
     * Sets the Engine settings.
     *
     * @param engine The Engine settings to set.
     */
    public void setEngine(Engine engine) {
        this.engine = engine;
    }

    /**
     * Serializes this WazuhSettings instance to a JSON string.
     *
     * @return The JSON representation, or null if serialization fails.
     */
    public String toJson() {
        try {
            return MAPPER.writeValueAsString(this);
        } catch (JsonProcessingException e) {
            return null;
        }
    }

    @Override
    public String toString() {
        return "WazuhSettings{" + "engine=" + this.engine + '}';
    }

    /**
     * Nested class representing Engine-specific settings.
     *
     * <p>Contains configuration options that control Engine behavior, such as whether to index raw
     * events. This class is designed to be extensible for future Engine-related settings.
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Engine {

        @JsonProperty(KEY_INDEX_RAW_EVENTS)
        private Boolean indexRawEvents;

        /** Default constructor for Jackson deserialization. Does not set defaults. */
        public Engine() {}

        /**
         * Constructs an Engine instance with the specified values.
         *
         * @param indexRawEvents Whether to index raw events.
         */
        @JsonCreator
        public Engine(@JsonProperty(KEY_INDEX_RAW_EVENTS) Boolean indexRawEvents) {
            this.indexRawEvents = indexRawEvents;
        }

        /**
         * Creates an Engine instance with default values.
         *
         * @return A new Engine instance with default settings.
         */
        public static Engine createDefault() {
            Engine engine = new Engine();
            engine.indexRawEvents = DEFAULT_INDEX_RAW_EVENTS;
            return engine;
        }

        /**
         * Gets whether raw events should be indexed.
         *
         * @return true if raw events should be indexed, false otherwise.
         */
        public Boolean getIndexRawEvents() {
            return this.indexRawEvents;
        }

        /**
         * Sets whether raw events should be indexed.
         *
         * @param indexRawEvents true to index raw events, false otherwise.
         */
        public void setIndexRawEvents(Boolean indexRawEvents) {
            this.indexRawEvents = indexRawEvents;
        }

        @Override
        public String toString() {
            return "Engine{" + "indexRawEvents=" + this.indexRawEvents + '}';
        }
    }
}
