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
package com.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;

import java.util.Map;

import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Class to represent an index that emulates the data stream layout using regular indices: a hidden
 * backing index (e.g., {@code .ds-<alias>-000001}) is created with a visible write alias matching
 * the configured name. ISM rolls the alias over and manages retention.
 *
 * <p>Used by indices that need data-stream-like rollover/retention but must remain mutable (i.e.,
 * allow {@code _update} on indexed documents), which data streams disallow.
 */
public class AliasedIndex extends IsmManagedIndex {
    private static final Logger log = LogManager.getLogger(AliasedIndex.class);

    private static final String BACKING_INDEX_PREFIX = ".ds-";
    private static final String BACKING_INDEX_SUFFIX = "-000001";
    private static final String HIDDEN_SETTING = "index.hidden";

    /**
     * Constructor.
     *
     * @param alias visible alias name (e.g., "wazuh-findings-v5-security"). Also used as the rollover
     *     alias.
     * @param template path to the index template resource (without .json extension).
     */
    public AliasedIndex(String alias, String template) {
        super(alias, template);
    }

    /** Backing-index pattern: {@code .ds-<alias>*}. */
    @Override
    protected String indexPattern() {
        return BACKING_INDEX_PREFIX + this.index + "*";
    }

    /**
     * Marks the template as hidden so rollover-created backing indices stay out of wildcard queries —
     * matching the explicit {@code index.hidden} setting on the initial backing index.
     */
    @Override
    protected void augmentSettings(Map<String, Object> settings) {
        settings.put(HIDDEN_SETTING, true);
    }

    /**
     * Builds a regular composable template (no {@code dataStreamTemplate}) so the materialized
     * indices behave like ordinary aliased indices, not data-stream backings.
     */
    @Override
    protected ComposableIndexTemplate buildComposableTemplate(
            IndexTemplate indexTemplate, Settings settings, CompressedXContent mappings) {
        return new ComposableIndexTemplate(
                indexTemplate.getIndexPatterns(),
                new Template(settings, mappings, null),
                null,
                indexTemplate.getPriority(),
                null,
                null,
                null);
    }

    /**
     * Creates the initial hidden backing index with the visible write alias. Skips creation if the
     * alias already exists.
     *
     * @param alias visible alias name.
     */
    @Override
    public void createIndex(String alias) {
        if (this.clusterService.state().getMetadata().hasAlias(alias)) {
            log.debug("Alias {} already exists. Skipping backing index creation.", alias);
            return;
        }

        String backingIndex = BACKING_INDEX_PREFIX + alias + BACKING_INDEX_SUFFIX;
        try {
            CreateIndexRequest request =
                    new CreateIndexRequest(backingIndex)
                            .settings(Settings.builder().put(HIDDEN_SETTING, true))
                            .alias(new Alias(alias).writeIndex(true));

            CreateIndexResponse response =
                    this.client
                            .admin()
                            .indices()
                            .create(request)
                            .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));

            log.info(
                    "Backing index created successfully: {} (alias: {}, acknowledged: {})",
                    response.index(),
                    alias,
                    response.isAcknowledged());
        } catch (ResourceAlreadyExistsException e) {
            log.info("Backing index {} already exists. Skipping.", backingIndex);
        } catch (Exception e) {
            // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            if (!this.retry_index_creation) {
                log.error(
                        "Initialization of backing index [{}] finally failed. The node will shut down.",
                        backingIndex);
                throw e;
            }
            log.warn("Operation to create the backing index [{}] timed out. Retrying...", backingIndex);
            this.retry_index_creation = false;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createIndex(alias);
        }
    }

    /**
     * Resolves the write target of the visible alias for ISM registration. After cluster restart this
     * dynamically picks up the current write backing index (e.g., {@code -000002} after a rollover),
     * not just the initial one.
     */
    @Override
    protected String resolveBackingIndexName() {
        IndexAbstraction abs =
                this.clusterService.state().metadata().getIndicesLookup().get(this.index);
        if (abs == null) {
            log.warn("Alias [{}] not found. Skipping ISM registration.", this.index);
            return null;
        }
        IndexMetadata writeIdx = abs.getWriteIndex();
        return writeIdx != null ? writeIdx.getIndex().getName() : null;
    }
}
