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
import org.opensearch.action.index.IndexRequest;
import org.opensearch.common.xcontent.XContentType;

import java.time.Instant;
import java.util.Map;

/**
 * Manages the {@code .wazuh-setup-status} index, which holds a single marker document describing
 * the state of this plugin's initialization. Other plugins (e.g. Content Manager) read this marker
 * to defer their startup work until all indices managed by this plugin have been created.
 *
 * <p>The marker transitions once per boot: {@value #SETUP_STATUS_INITIALIZING} at the beginning of
 * the initialization, {@value #SETUP_STATUS_COMPLETE} once every index has been initialized.
 */
public class SetupStatusIndex extends WazuhIndex {
    private static final Logger log = LogManager.getLogger(SetupStatusIndex.class);

    /** Index name for the setup status marker. */
    public static final String INDEX_NAME = ".wazuh-setup-status";

    /** Document ID for the setup initialization status marker. */
    public static final String SETUP_STATUS_ID = "setup-status";

    /** Marker status while index initialization is in progress. */
    public static final String SETUP_STATUS_INITIALIZING = "initializing";

    /** Marker status once index initialization has finished. */
    public static final String SETUP_STATUS_COMPLETE = "complete";

    /** JSON key for the marker status field. */
    public static final String KEY_STATUS = "status";

    /** JSON key for the marker timestamp field. */
    public static final String KEY_TIMESTAMP = "timestamp";

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    public SetupStatusIndex(String index, String template) {
        super(index, template);
    }

    /**
     * Invalidates any setup status marker left over from a previous boot by overwriting it with
     * {@value #SETUP_STATUS_INITIALIZING}. Skipped when the index does not exist yet: there is no
     * stale marker to invalidate, and writing would auto-create the index without its template.
     */
    public void markInitializing() {
        if (!this.indexExists(INDEX_NAME)) {
            log.debug("Index {} does not exist. No setup status marker to invalidate.", INDEX_NAME);
            return;
        }
        this.setSetupStatus(SETUP_STATUS_INITIALIZING);
    }

    /**
     * Persists the setup status marker with {@value #SETUP_STATUS_COMPLETE}, signaling that all
     * indices managed by this plugin have been initialized.
     */
    public void markComplete() {
        this.setSetupStatus(SETUP_STATUS_COMPLETE);
    }

    /**
     * Writes the setup status marker document. Failures are logged but never propagated, so they
     * cannot interrupt node startup.
     *
     * @param status marker status value to persist.
     */
    private void setSetupStatus(String status) {
        try {
            IndexRequest request =
                    new IndexRequest(INDEX_NAME)
                            .id(SETUP_STATUS_ID)
                            .source(
                                    Map.of(KEY_STATUS, status, KEY_TIMESTAMP, Instant.now().toString()),
                                    XContentType.JSON);
            this.client.index(request).actionGet();
            log.info("Setup status marker set to [{}].", status);
        } catch (Exception e) {
            log.error("Could not write setup status marker [{}]: {}", status, e.getMessage());
        }
    }
}
