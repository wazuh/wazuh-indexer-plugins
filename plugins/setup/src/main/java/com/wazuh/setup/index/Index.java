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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.settings.PluginSettings;
import com.wazuh.setup.utils.JsonUtils;

/**
 * Abstract class with the required logic to create indices. In our context, an index always require
 * an index template describing the index schema (mappings) and settings.
 *
 * @see IndexInitializer
 */
public abstract class Index implements IndexInitializer {
    private static final Logger log = LogManager.getLogger(Index.class);

    // Dependencies.
    Client client;
    ClusterService clusterService;
    JsonUtils jsonUtils;

    // Properties.
    protected String index;
    protected String template;

    /**
     * Re-attempts already spent on index and index-template creation. Each is compared against {@code
     * plugins.setup.max_retries} at failure time rather than captured up front, because the cluster
     * service these settings come from is injected after construction.
     */
    int indexCreationAttempts;

    int templateCreationAttempts;

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    Index(String index, String template) {
        this.index = index;
        this.template = template;

        this.indexCreationAttempts = 0;
        this.templateCreationAttempts = 0;
    }

    /**
     * Sets the OpenSearch client.
     *
     * @param client OpenSearch client.
     */
    public void setClient(Client client) {
        this.client = client;
    }

    /**
     * Sets the ClusterService.
     *
     * @param clusterService OpenSearch ClusterService.
     */
    public void setClusterService(ClusterService clusterService) {
        this.clusterService = clusterService;
    }

    /**
     * Sets the JsonUtils instance.
     *
     * @param jsonUtils the JsonUtils instance to set.
     */
    public void setUtils(JsonUtils jsonUtils) {
        this.jsonUtils = jsonUtils;
    }

    /**
     * Index name getter.
     *
     * @return the name of the index, data stream or alias this instance manages.
     */
    public String getIndexName() {
        return this.index;
    }

    /**
     * Returns whether the index takes part in the schema versioning: its template carries the {@code
     * schema_version} and {@code compat_version} the Setup plugin compares on every boot.
     *
     * @return true by default.
     */
    public boolean isVersioned() {
        return true;
    }

    /**
     * Reads the index template this index is created from.
     *
     * @return the parsed template.
     * @throws IOException if the template resource cannot be read or parsed.
     * @throws IllegalArgumentException if the template resource does not exist, which is a packaging
     *     defect.
     */
    protected IndexTemplate loadTemplate() throws IOException {
        return this.loadTemplate(this.template);
    }

    /**
     * Reads an index template shipped with the plugin.
     *
     * @param template path of the template resource, without the .json extension.
     * @return the parsed template.
     * @throws IOException if the template resource cannot be read or parsed.
     * @throws IllegalArgumentException if the template resource does not exist, which is a packaging
     *     defect.
     */
    protected IndexTemplate loadTemplate(String template) throws IOException {
        ObjectMapper mapper = new ObjectMapper();
        try (InputStream is =
                this.getClass().getClassLoader().getResourceAsStream(template + ".json")) {
            if (is == null) {
                throw new IllegalArgumentException(
                        "Index template resource [" + template + ".json] not found");
            }
            return mapper.readValue(is, IndexTemplate.class);
        }
    }

    /**
     * Resolves the concrete index that holds the data right now: the index itself, the write index of
     * a data stream, or the write index behind an alias.
     *
     * @return the metadata of the live index, or null when the name resolves to nothing.
     */
    public IndexMetadata resolveLiveIndex() {
        IndexAbstraction abstraction =
                this.clusterService.state().metadata().getIndicesLookup().get(this.index);
        if (abstraction == null) {
            return null;
        }
        IndexMetadata writeIndex = abstraction.getWriteIndex();
        if (writeIndex != null) {
            return writeIndex;
        }
        List<IndexMetadata> indices = abstraction.getIndices();
        return indices == null || indices.isEmpty() ? null : indices.getFirst();
    }

    /**
     * Reads the schema version the live index carries in its mapping {@code _meta}, inherited from
     * the template it was created with.
     *
     * @return the installed schema version, or {@code 0} when the index does not exist or carries no
     *     version.
     */
    public long getInstalledSchemaVersion() {
        IndexMetadata liveIndex = this.resolveLiveIndex();
        if (liveIndex == null) {
            log.warn(
                    "Index [{}] resolves to no concrete index. Its schema version is unknown.", this.index);
            return 0;
        }
        MappingMetadata mapping = liveIndex.mapping();
        if (mapping == null) {
            return 0;
        }
        Object meta = mapping.sourceAsMap().get(IndexTemplate.META_KEY);
        if (!(meta instanceof Map)) {
            return 0;
        }
        Object version = ((Map<?, ?>) meta).get(IndexTemplate.SCHEMA_VERSION_KEY);
        return version instanceof Number ? ((Number) version).longValue() : 0;
    }

    /**
     * Returns the name the index template is stored under in the cluster. By default it is the
     * template path without the "templates/" prefix and with slashes turned into hyphens, so {@code
     * templates/streams/alerts} is stored as {@code streams-alerts}.
     *
     * @param templatePath the template path (e.g., "templates/streams/alerts")
     * @return the template name (e.g., "streams-alerts")
     */
    protected String templateName(String templatePath) {
        templatePath = templatePath.replaceFirst("^templates/", "");
        return templatePath.replace("/", "-");
    }

    /**
     * Adjusts the shipped template before it is stored, for instance to narrow its index patterns to
     * this index. Does nothing by default.
     *
     * @param indexTemplate the parsed template, modified in place.
     */
    protected void customizeTemplate(IndexTemplate indexTemplate) {}

    /**
     * Returns whether the index exists.
     *
     * @param indexName the name of the index to check.
     * @return true if the index exists on the cluster, false otherwise.
     */
    public boolean indexExists(String indexName) {
        return this.clusterService.state().getRoutingTable().hasIndex(indexName);
    }

    /**
     * Creates an index.
     *
     * @param index Name of the index to create.
     */
    public void createIndex(String index) {
        try {
            if (!this.indexExists(index)) {
                CreateIndexRequest request = new CreateIndexRequest(index);
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
        } catch (ResourceAlreadyExistsException e) {
            log.debug("Index {} already exists. Skipping.", index);
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index also failed. Original exception is rethrown.
            if (this.indexCreationAttempts
                    >= PluginSettings.getMaxRetries(this.clusterService.getSettings())) {
                log.error("Initialization of index [{}] finally failed. The node will shut down.", index);
                throw e;
            }
            log.warn("Operation to create the index [{}] timed out. Retrying...", index);
            this.indexCreationAttempts++;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createIndex(index);
        }
    }

    /**
     * Creates an index template (v2).
     *
     * @param template name of the index template to create.
     */
    public void createTemplate(String template) {
        // Get the template name
        String templateName = this.templateName(template);

        try {
            // Read JSON index template
            ObjectMapper mapper = new ObjectMapper();
            IndexTemplate indexTemplate = this.loadTemplate(template);
            indexTemplate.validateSchemaVersions(templateName);
            this.customizeTemplate(indexTemplate);

            // Create a V2 template (ComposableIndexTemplate)
            String indexMappings = mapper.writeValueAsString(indexTemplate.getMappings());
            CompressedXContent compressedMapping = new CompressedXContent(indexMappings);
            Settings settings = Settings.builder().loadFromMap(indexTemplate.getSettings()).build();
            ComposableIndexTemplate composableTemplate =
                    indexTemplate.getComposableIndexTemplate(settings, compressedMapping);

            // Use the V2 API to put the template
            PutComposableIndexTemplateAction.Request request =
                    new PutComposableIndexTemplateAction.Request(templateName)
                            .indexTemplate(composableTemplate)
                            .create(false);

            // Put index template
            this.client
                    .execute(PutComposableIndexTemplateAction.INSTANCE, request)
                    .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
        } catch (IOException e) {
            log.error(
                    "Error reading index template from filesystem [{}]. Caused by: {}",
                    template,
                    e.toString());
        } catch (IllegalArgumentException e) {
            // A template without its schema versions is a packaging defect, not a transient
            // failure: no retry, and the initialization fails naming the template.
            log.error("Invalid index template [{}]: {}", template, e.getMessage());
            throw e;
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index template {} already exists. Skipping.", templateName);
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index template also failed. Original exception is
            // rethrown.
            if (this.templateCreationAttempts
                    >= PluginSettings.getMaxRetries(this.clusterService.getSettings())) {
                log.error(
                        "Initialization of index template [{}] finally failed. The node will shut down.",
                        template);
                throw e;
            }
            log.warn("Operation to create the index template [{}] timed out. Retrying...", template);
            this.templateCreationAttempts++;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createTemplate(template);
        }
    }

    /**
     * Initializes the index. Usually implies invoking {@link #createTemplate(String)} and {@link
     * #createIndex(String)}, in that order.
     */
    public void initialize() {
        this.createTemplate(this.template);
        this.createIndex(this.index);
    }

    /**
     * Utility method to wrap up the call to {@link Thread#sleep(long)} on a try-catch block.
     *
     * @param millis sleep interval in milliseconds.
     */
    void sleep(long millis) {
        try {
            Thread.sleep(millis);
        } catch (InterruptedException ex) {
            throw new RuntimeException(ex);
        }
    }
}
