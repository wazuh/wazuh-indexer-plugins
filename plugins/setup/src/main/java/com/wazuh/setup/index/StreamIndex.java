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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.admin.indices.datastream.CreateDataStreamAction;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.clustermanager.AcknowledgedResponse;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.DataStream;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.index.Index;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.index.engine.VersionConflictEngineException;

import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Class to represent a Stream index. Stream indices contain time-based events of any kind (alerts,
 * statistics, logs...).
 */
public class StreamIndex extends WazuhIndex {
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
     * Overrides createTemplate to apply dynamic properties specific to stream indices.
     *
     * @param template name of the index template to create.
     */
    @Override
    public void createTemplate(String template) {
        String templateName = this.index + "-template";

        try {
            ObjectMapper mapper = new ObjectMapper();
            InputStream is = this.getClass().getClassLoader().getResourceAsStream(template + ".json");
            IndexTemplate indexTemplate = mapper.readValue(is, IndexTemplate.class);

            // Dynamically set the index patterns to match this specific index
            indexTemplate.setIndexPatterns(List.of(this.index + "*"));

            // Dynamically update the rollover alias if it exists in the base template
            Map<String, Object> settingsMap = indexTemplate.getSettings();
            if (settingsMap != null
                    && settingsMap.containsKey("plugins.index_state_management.rollover_alias")) {
                settingsMap.put("plugins.index_state_management.rollover_alias", this.index);
            }

            String indexMappings = mapper.writeValueAsString(indexTemplate.getMappings());
            CompressedXContent compressedMapping = new CompressedXContent(indexMappings);
            Settings settings = Settings.builder().loadFromMap(indexTemplate.getSettings()).build();
            ComposableIndexTemplate composableTemplate =
                    indexTemplate.getComposableIndexTemplate(settings, compressedMapping);

            PutComposableIndexTemplateAction.Request request =
                    new PutComposableIndexTemplateAction.Request(templateName)
                            .indexTemplate(composableTemplate)
                            .create(false);

            this.client
                    .execute(PutComposableIndexTemplateAction.INSTANCE, request)
                    .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
        } catch (IOException e) {
            log.error(
                    "Error reading index template from filesystem [{}]. Caused by: {}",
                    template,
                    e.toString());
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index template {} already exists. Skipping.", templateName);
        } catch (Exception e) {
            if (!this.retry_template_creation) {
                log.error(
                        "Initialization of index template [{}] finally failed. The node will shut down.",
                        templateName);
                throw e;
            }
            log.warn("Operation to create the index template [{}] timed out. Retrying...", templateName);
            this.retry_template_creation = false;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createTemplate(template);
        }
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
     * Overrides {@link com.wazuh.setup.index.Index#initialize()} to also register the backing index
     * with ISM after creating the data stream.
     */
    @Override
    public void initialize() {
        this.createTemplate(this.template);
        this.createIndex(this.index);
        this.registerWithISM();
    }

    /**
     * Registers the data stream's backing index with ISM by writing a {@code ManagedIndexConfig}
     * document directly to {@code .opendistro-ism-config}. This is necessary because ISM policies
     * indexed directly (bypassing the ISM API) do not register their {@code ism_template} patterns
     * with the ISM coordinator cache, so backing indices of data streams would not be auto-detected.
     */
    private void registerWithISM() {
        DataStream dataStream = this.clusterService.state().metadata().dataStreams().get(this.index);
        if (dataStream == null) {
            log.warn("Data stream [{}] not found. Skipping ISM registration.", this.index);
            return;
        }

        List<Index> indices = dataStream.getIndices();
        if (indices == null || indices.isEmpty()) {
            log.warn(
                    "Data stream [{}] has no backing indices in cluster state. Skipping ISM registration.",
                    this.index);
            return;
        }
        String backingIndex = indices.getLast().getName();

        IndexMetadata indexMetadata = this.clusterService.state().metadata().index(backingIndex);
        if (indexMetadata == null) {
            log.warn(
                    "Index metadata for [{}] not found in cluster state. Skipping ISM registration.",
                    backingIndex);
            return;
        }

        String policyId =
                indexMetadata.getSettings().get("index.plugins.index_state_management.policy_id");
        if (policyId == null) {
            log.warn("No ISM policy_id setting found for [{}]. Skipping ISM registration.", backingIndex);
            return;
        }

        try {
            String indexUuid = indexMetadata.getIndexUUID();
            long timeout = PluginSettings.getTimeout(this.clusterService.getSettings());

            // Skip if already registered
            GetResponse existing =
                    this.client
                            .get(new GetRequest(IndexStateManagement.ISM_INDEX_NAME).id(indexUuid))
                            .actionGet(timeout);
            if (existing.isExists()) {
                log.debug("Backing index [{}] is already registered with ISM. Skipping.", backingIndex);
                return;
            }

            // Fetch the full ISM policy
            GetResponse policyResponse =
                    this.client
                            .get(new GetRequest(IndexStateManagement.ISM_INDEX_NAME).id(policyId))
                            .actionGet(timeout);
            if (!policyResponse.isExists()) {
                log.warn(
                        "ISM policy [{}] not found. Skipping ISM registration for [{}].",
                        policyId,
                        backingIndex);
                return;
            }

            long now = Instant.now().toEpochMilli();

            // Build a ManagedIndexConfig document and index it into .opendistro-ism-config
            // keyed by the backing index's UUID. This is equivalent to calling the
            // POST _plugins/_ism/add/<index> API: the ISM plugin will pick up this
            // document on its next sweep and start managing the index according to
            // the embedded policy. OpType.CREATE ensures only one node wins in a
            // multi-node cluster (atomic create-if-absent).
            Map<String, Object> doc =
                    Map.of(
                            "managed_index",
                            Map.ofEntries(
                                    Map.entry("name", backingIndex),
                                    Map.entry("index", backingIndex),
                                    Map.entry("index_uuid", indexUuid),
                                    Map.entry("enabled", true),
                                    Map.entry("enabled_time", now),
                                    Map.entry("last_updated_time", now),
                                    Map.entry("policy_id", policyId),
                                    Map.entry("policy_seq_no", policyResponse.getSeqNo()),
                                    Map.entry("policy_primary_term", policyResponse.getPrimaryTerm()),
                                    Map.entry("policy", policyResponse.getSourceAsMap().get("policy")),
                                    Map.entry(
                                            "schedule",
                                            Map.of(
                                                    "interval", Map.of("period", 1, "unit", "Minutes", "start_time", now)))));

            this.client
                    .index(
                            new IndexRequest(IndexStateManagement.ISM_INDEX_NAME)
                                    .id(indexUuid)
                                    .opType(DocWriteRequest.OpType.CREATE)
                                    .source(doc, MediaTypeRegistry.JSON))
                    .actionGet(timeout);
            log.info("Registered backing index [{}] with ISM policy [{}]", backingIndex, policyId);
        } catch (VersionConflictEngineException e) {
            log.debug("Backing index [{}] is already registered with ISM. Skipping.", backingIndex);
        } catch (Exception e) {
            log.warn("Failed to register [{}] with ISM: {}", backingIndex, e.getMessage());
        }
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
