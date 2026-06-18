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
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;

import java.time.Instant;
import java.util.Map;

/**
 * Manages the {@code .wazuh-setup-status} index, which holds a single marker document describing
 * the state of this plugin's initialization. Other plugins (e.g. Content Manager) read this marker
 * to defer their startup work until all indices managed by this plugin have been created.
 *
 * <p>The marker transitions once per boot: {@value #SETUP_STATUS_RUNNING} as soon as this index has
 * been created (or confirmed to already exist) by {@link #initialize()} — which {@link
 * com.wazuh.setup.SetupPlugin} runs first, ahead of every other index, so the marker is invalidated
 * as early as possible — then either {@value #SETUP_STATUS_READY} once every index has been
 * initialized, or {@value #SETUP_STATUS_FAILED} if initialization could not complete.
 */
public class SetupStatusIndex extends WazuhIndex {
    private static final Logger log = LogManager.getLogger(SetupStatusIndex.class);

    /** Index name for the setup status marker. */
    public static final String INDEX_NAME = ".wazuh-setup-status";

    /** Document ID for the setup initialization status marker. */
    public static final String SETUP_STATUS_ID = "setup-status";

    /** Marker status while index initialization is in progress. */
    public static final String SETUP_STATUS_RUNNING = "running";

    /** Marker status once index initialization has finished successfully. */
    public static final String SETUP_STATUS_READY = "ready";

    /** Marker status when index initialization could not complete. */
    public static final String SETUP_STATUS_FAILED = "failed";

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
     * Creates this index (or confirms it already exists) and immediately invalidates any setup
     * status marker left over from a previous boot by overwriting it with {@value
     * #SETUP_STATUS_RUNNING}. Doing both in the same call, on the same thread, avoids relying on
     * {@link #indexExists(String)} — which checks the cluster's routing table and can still report
     * "does not exist" for a brief window right after a restart, even when the index is already on
     * disk, causing the {@code running} write to be silently skipped.
     */
    @Override
    public void initialize() {
        this.createTemplate(this.template);
        this.createIndex(this.index);
        this.markRunning();
    }

    /**
     * Persists the setup status marker with {@value #SETUP_STATUS_RUNNING}. Only called from {@link
     * #initialize()}, right after this index has been created or confirmed to already exist, so the
     * write is always safe.
     */
    public void markRunning() {
        this.setSetupStatus(SETUP_STATUS_RUNNING);
    }

    /**
     * Persists the setup status marker with {@value #SETUP_STATUS_READY}, signaling that all indices
     * managed by this plugin have been initialized.
     */
    public void markReady() {
        this.setSetupStatus(SETUP_STATUS_READY);
    }

    /**
     * Persists the setup status marker with {@value #SETUP_STATUS_FAILED}, signaling that index
     * initialization could not complete during this boot.
     */
    public void markFailed() {
        this.setSetupStatus(SETUP_STATUS_FAILED);
    }

    /**
     * Writes the setup status marker document. Failures are logged but never propagated, so they
     * cannot interrupt node startup.
     *
     * <p>Periodic refresh is disabled on this index ({@code refresh_interval: -1}) since it only
     * changes on startup, so each write triggers an immediate refresh to keep the marker searchable.
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
                                    XContentType.JSON)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            this.client.index(request).actionGet();
            log.info("Setup status marker set to [{}].", status);
        } catch (Exception e) {
            log.error("Could not write setup status marker [{}]: {}", status, e.getMessage());
        }
    }
}
