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
import org.opensearch.action.admin.indices.datastream.CreateDataStreamAction;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.metadata.DataStream;

import java.util.List;

import com.wazuh.setup.settings.PluginSettings;

/**
 * Class to represent a Stream index. Stream indices contain time-based events of any kind (alerts,
 * statistics, logs...).
 */
public class StreamIndex extends IsmManagedIndex {
    private static final Logger log = LogManager.getLogger(StreamIndex.class);

    /**
     * Constructor. Uses the default "main" stream template.
     *
     * @param index index name (e.g., "wazuh-events-v5-access-management").
     */
    public StreamIndex(String index) {
        super(index, "templates/streams/events");
    }

    /**
     * Constructor with a custom template path.
     *
     * @param index index name (e.g., "wazuh-events-raw-v5").
     * @param template path to the index template resource (without .json extension).
     */
    public StreamIndex(String index, String template) {
        super(index, template);
    }

    /**
     * Overrides {@link com.wazuh.setup.index.Index#createIndex(String)} to create a Data Stream
     * instead.
     *
     * @param index Name of the data stream to create.
     */
    @Override
    public void createIndex(String index) {
        try {
            this.createDataStream(index);
        } catch (ResourceAlreadyExistsException e) {
            log.info("Data stream {} already exists. Skipping.", index);
        } catch (Exception e) {
            // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the data stream also failed. Original exception is
            // rethrown.
            if (!this.retry_index_creation) {
                log.error(
                        "Initialization of data stream [{}] finally failed. The node will shut down.", index);
                throw e;
            }
            log.warn("Operation to create the data stream [{}] timed out. Retrying...", index);
            this.retry_index_creation = false;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createIndex(index);
        }
    }

    /**
     * Resolves the data stream's write backing index (the latest one in the stream) for ISM
     * registration.
     */
    @Override
    protected String resolveBackingIndexName() {
        DataStream dataStream = this.clusterService.state().metadata().dataStreams().get(this.index);
        if (dataStream == null) {
            log.warn("Data stream [{}] not found. Skipping ISM registration.", this.index);
            return null;
        }

        List<org.opensearch.core.index.Index> indices = dataStream.getIndices();
        if (indices == null || indices.isEmpty()) {
            log.warn(
                    "Data stream [{}] has no backing indices in cluster state. Skipping ISM registration.",
                    this.index);
            return null;
        }
        return indices.getLast().getName();
    }

    /**
     * Creates a Data Stream.
     *
     * @param name name of the data stream to create.
     */
    public void createDataStream(String name) {
        CreateDataStreamAction.Request request = new CreateDataStreamAction.Request(name);

        AcknowledgedResponse response =
                this.client
                        .admin()
                        .indices()
                        .createDataStream(request)
                        .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));

        log.info("Data Stream created successfully: {} {}", name, response.isAcknowledged());
    }
}
