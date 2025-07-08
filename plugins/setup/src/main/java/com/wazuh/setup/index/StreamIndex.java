/*
 * Copyright (C) 2024, Wazuh Inc.
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
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;

import com.wazuh.setup.settings.PluginSettings;

/**
 * Class to represent a Stream index. Stream indices contain time-based events of any kind (alerts,
 * statistics, logs...).
 */
public class StreamIndex extends WazuhIndex {
    private static final Logger log = LogManager.getLogger(StreamIndex.class);

    private final String alias;

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     * @param alias index alias name for advanced management such as automatic rollover.
     */
    public StreamIndex(String index, String template, String alias) {
        super(index, template);
        this.alias = alias;
    }

    /**
     * Overrides {@link Index#createIndex(String)} to include the {@link #alias} to the index creation
     * request.
     *
     * @param index Name of the index to create.
     * @see Alias
     */
    @Override
    public void createIndex(String index) {
        try {
            if (!this.indexExists(index)) {
                CreateIndexRequest request =
                        new CreateIndexRequest(index).alias(new Alias(this.alias).writeIndex(true));
                CreateIndexResponse createIndexResponse =
                        this.client
                                .admin()
                                .indices()
                                .create(request)
                                .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
                log.info(
                        "Index created successfully: {} {}",
                        createIndexResponse.index(),
                        createIndexResponse.isAcknowledged());
            }
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index also failed. Original exception is rethrown.
            if (!this.retry_index_creation) {
                log.error("Initialization of index [{}] finally failed. The node will shut down.", index);
                throw e;
            }
            log.warn("Operation to create the index [{}] timed out. Retrying...", index);
            this.retry_index_creation = false;
            this.indexUtils.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createIndex(index);
        }
    }
}
