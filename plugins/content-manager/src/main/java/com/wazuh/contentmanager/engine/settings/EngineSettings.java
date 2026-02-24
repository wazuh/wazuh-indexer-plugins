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
package com.wazuh.contentmanager.engine.settings;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Manages the lifecycle of engine settings stored in the {@code .wazuh-settings} index. Responsible
 * for ensuring the default settings document exists at node startup.
 */
public class EngineSettings {
    private static final Logger log = LogManager.getLogger(EngineSettings.class);
    private static final ObjectMapper mapper = new ObjectMapper();

    private final ContentIndex settingsIndex;

    /**
     * Construct the engine settings manager.
     *
     * @param settingsIndex the ContentIndex wrapping {@code .wazuh-settings}
     */
    public EngineSettings(ContentIndex settingsIndex) {
        this.settingsIndex = settingsIndex;
    }

    /**
     * Ensures the default engine settings document exists. If no document is found for the settings
     * ID, a default document with {@code engine.index_raw_events = false} is persisted. If the
     * document already exists, this method is a no-op.
     */
    public void initialize() {
        try {
            JsonNode existing = this.settingsIndex.getDocument(PluginSettings.ENGINE_SETTINGS_ID);
            if (existing != null) {
                log.debug("Engine settings already initialized.");
                return;
            }
            ObjectNode defaults = mapper.createObjectNode();
            ObjectNode engine = mapper.createObjectNode();
            engine.put(Constants.KEY_INDEX_RAW_EVENTS, false);
            defaults.set(Constants.KEY_ENGINE, engine);
            this.settingsIndex.indexDocument(PluginSettings.ENGINE_SETTINGS_ID, defaults);
            log.info("Default engine settings initialized.");
        } catch (Exception e) {
            log.warn("Could not initialize default engine settings: {}", e.getMessage());
        }
    }
}
