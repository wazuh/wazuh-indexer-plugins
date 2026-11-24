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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.mapping.put.PutMappingRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.xcontent.XContentType;

import java.io.IOException;
import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Manages the {@code .wazuh-setup-status} index, which holds a marker document describing the state
 * of this plugin's initialization, plus one record per managed index with its schema versions.
 * Other plugins (e.g. Content Manager) read the marker to defer their startup work until all
 * indices managed by this plugin have been created and are at the shipped schema version.
 *
 * <p>The marker transitions once per boot: {@value #SETUP_STATUS_RUNNING} as soon as this index has
 * been created (or confirmed to already exist) by {@link #initialize()} — which {@link
 * com.wazuh.setup.SetupPlugin} runs first, ahead of every other index, so the marker is invalidated
 * as early as possible — then either {@value #SETUP_STATUS_READY} once every index has been
 * initialized and none needs an upgrade, or {@value #SETUP_STATUS_FAILED} if initialization could
 * not complete. While an index still needs an upgrade the marker stays {@value
 * #SETUP_STATUS_RUNNING}.
 *
 * <p>The per-index records are written by {@link SchemaDriftDetector} and read back on the next
 * boot, so an upgrade interrupted half-way resumes from the step it recorded. Their document id is
 * the index name.
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
     * Creates this index (or confirms it already exists), brings its mapping up to the shipped one,
     * and immediately invalidates any setup status marker left over from a previous boot by
     * overwriting it with {@value #SETUP_STATUS_RUNNING}. Doing all of it in the same call, on the
     * same thread, avoids relying on {@link #indexExists(String)} — which checks the cluster's
     * routing table and can still report "does not exist" for a brief window right after a restart,
     * even when the index is already on disk, causing the {@code running} write to be silently
     * skipped.
     */
    @Override
    public void initialize() {
        this.createTemplate(this.template);
        this.createIndex(this.index);
        this.updateMapping();
        this.markRunning();
    }

    /**
     * Pushes the shipped mappings to the existing index. A stored template only applies to indices
     * created afterwards, and this index outlives upgrades because it holds the upgrade records of
     * every other index. Its mapping is strict, so a record field added by a newer version would be
     * rejected until the mapping is updated: this index upgrades itself in place, on every boot, so
     * it can always hold the records of the version that is running. The update is idempotent and
     * only ever adds fields.
     */
    private void updateMapping() {
        try {
            IndexTemplate indexTemplate = this.loadTemplate();
            String mappings = new ObjectMapper().writeValueAsString(indexTemplate.getMappings());
            this.client
                    .admin()
                    .indices()
                    .putMapping(new PutMappingRequest(INDEX_NAME).source(mappings, XContentType.JSON))
                    .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
            log.debug("Mapping of [{}] is up to date with the shipped template.", INDEX_NAME);
        } catch (IOException e) {
            log.error(
                    "Error reading index template from filesystem [{}]. Caused by: {}",
                    this.template,
                    e.toString());
        } catch (Exception e) {
            // The records of the running version cannot be stored until the mapping is updated,
            // which the next boot retries. The marker writes below only use the original fields.
            log.error("Could not update the mapping of [{}]: {}", INDEX_NAME, e.getMessage());
        }
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
     * managed by this plugin have been initialized and are at the shipped schema version.
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
     * Reads the schema version record of an index.
     *
     * @param index name of the index, data stream or alias.
     * @return the record, or empty when none was written yet.
     * @throws IllegalArgumentException if the stored record is malformed.
     */
    public Optional<IndexRecord> getIndexRecord(String index) {
        GetResponse response =
                this.client
                        .get(new GetRequest(INDEX_NAME).id(index))
                        .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
        if (!response.isExists()) {
            return Optional.empty();
        }
        return Optional.of(IndexRecord.fromMap(response.getSourceAsMap()));
    }

    /**
     * Writes the schema version record of an index, replacing the previous one. Unlike the marker, a
     * failure propagates: the records drive the upgrades of the other indices, so an initialization
     * that cannot store them has failed.
     *
     * @param record the record to persist.
     */
    public void putIndexRecord(IndexRecord record) {
        IndexRequest request =
                new IndexRequest(INDEX_NAME)
                        .id(record.index())
                        .source(record.toMap(), XContentType.JSON)
                        .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
        this.client
                .index(request)
                .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
        log.debug("Schema version record written: {}", record);
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
