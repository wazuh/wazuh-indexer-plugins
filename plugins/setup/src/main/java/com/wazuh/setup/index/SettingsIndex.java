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
package com.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.xcontent.XContentType;

import com.wazuh.setup.model.WazuhSettings;

/**
 * Manages the {@code .wazuh-settings} index document lifecycle. Responsible for writing the default
 * settings document at cluster startup (if absent) and providing document write operations for the
 * REST handler.
 */
public class SettingsIndex extends WazuhIndex {
    private static final Logger log = LogManager.getLogger(SettingsIndex.class);

    /** Index name for Wazuh settings. */
    public static final String INDEX_NAME = ".wazuh-settings";

    /** Document ID for the settings document. */
    public static final String SETTINGS_ID = "1";

    /** REST endpoint URI. */
    public static final String SETTINGS_URI = "/_plugins/_setup/settings";

    // Response messages
    public static final String S_200_SETTINGS_UPDATED = "Settings updated successfully.";
    public static final String E_400_INVALID_REQUEST_BODY = "Invalid request body.";
    public static final String E_400_MISSING_FIELD = "Missing required field: '%s'.";
    public static final String E_400_INVALID_TYPE = "Field '%s' must be of type %s.";
    public static final String E_500_INTERNAL_SERVER_ERROR = "Internal Server Error.";

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    public SettingsIndex(String index, String template) {
        super(index, template);
    }

    @Override
    public void initialize() {
        this.createTemplate(this.template);
        this.createIndex(this.index);
        this.indexDefaultValues();
    }

    /**
     * Ensures the default settings document exists. If no document is found for the settings ID, a
     * default document with {@code engine.index_raw_events = false} is persisted. If the document
     * already exists, this method is a no-op.
     */
    public void indexDefaultValues() {
        try {
            GetResponse response = this.client.prepareGet(INDEX_NAME, SETTINGS_ID).get();
            if (response.isExists()) {
                log.debug("Wazuh settings already initialized.");
                return;
            }

            WazuhSettings defaults = WazuhSettings.createDefault();
            IndexRequest request =
                    new IndexRequest(INDEX_NAME).id(SETTINGS_ID).source(defaults.toJson(), XContentType.JSON);
            this.client.index(request).actionGet();
            log.info("Default Wazuh settings initialized.");
        } catch (Exception e) {
            log.warn("Could not initialize default Wazuh settings: {}", e.getMessage());
        }
    }

    /**
     * Indexes a WazuhSettings document.
     *
     * @param settings the WazuhSettings to persist
     */
    public void indexDocument(WazuhSettings settings) {
        IndexRequest request =
                new IndexRequest(INDEX_NAME).id(SETTINGS_ID).source(settings.toJson(), XContentType.JSON);
        this.client.index(request).actionGet();
    }
}
