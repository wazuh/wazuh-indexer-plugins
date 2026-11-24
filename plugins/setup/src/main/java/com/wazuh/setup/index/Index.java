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

import com.wazuh.setup.config.SetupConfig;
import com.wazuh.setup.config.SupportedSetting;
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

    /** Value of {@code index.auto_expand_replicas} when the replica count is fixed. */
    private static final String AUTO_EXPAND_DISABLED = "false";

    // Dependencies.
    Client client;
    ClusterService clusterService;
    JsonUtils jsonUtils;

    /** Overrides read from the configuration file of the plugin. None until one is set. */
    SetupConfig config = SetupConfig.EMPTY;

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
     * Sets the configuration read from the configuration file of the plugin.
     *
     * @param config the configuration to take the overrides from.
     */
    public void setConfig(SetupConfig config) {
        this.config = config;
    }

    /**
     * Returns the resource path of the index template of this index.
     *
     * @return the path, without the .json extension (e.g., "templates/streams/events").
     */
    public String getTemplate() {
        return this.template;
    }

    /**
     * Builds the settings of an index template: the bundled settings, with the overrides of the
     * configuration file on top. Without overrides the result is the bundled settings, unchanged.
     *
     * @param template resource path of the index template (e.g., "templates/streams/events").
     * @param templateName name the index template is stored under.
     * @param indexTemplate the bundled index template.
     * @return the settings to store in the index template.
     */
    Settings templateSettings(String template, String templateName, IndexTemplate indexTemplate) {
        Settings.Builder bundled = Settings.builder().loadFromMap(indexTemplate.getSettings());
        Settings overrides = this.config.templateOverrides(template);
        if (overrides.isEmpty()) {
            return bundled.build();
        }
        Settings settings = bundled.put(overrides).build();
        String autoExpand = SupportedSetting.AUTO_EXPAND_REPLICAS.read(settings);
        if (overrides.hasValue(SupportedSetting.NUMBER_OF_REPLICAS.key())
                && !AUTO_EXPAND_DISABLED.equals(autoExpand)) {
            log.warn(
                    "Index template [{}]: the override of [{}] has no effect while [{}] is [{}], which takes precedence over the replica count. Set it to false to use a fixed number of replicas.",
                    templateName,
                    SupportedSetting.NUMBER_OF_REPLICAS.key(),
                    SupportedSetting.AUTO_EXPAND_REPLICAS.key(),
                    settings.get(SupportedSetting.AUTO_EXPAND_REPLICAS.key(), autoExpand));
        }
        this.warnIfExistingIndexDiffers(overrides);
        return settings;
    }

    /**
     * Warns about each overridden setting that the existing index does not have. An override changes
     * the index template, and a template only reaches the indices created after it.
     *
     * <p>The index looked at is the one new documents go to: the index itself, the index behind the
     * alias, or the last backing index of the data stream.
     *
     * @param overrides the settings the configuration file overrides for this index.
     */
    private void warnIfExistingIndexDiffers(Settings overrides) {
        IndexAbstraction existing =
                this.clusterService.state().metadata().getIndicesLookup().get(this.index);
        IndexMetadata writeIndex = existing == null ? null : existing.getWriteIndex();
        if (writeIndex == null) {
            return;
        }
        Settings current = writeIndex.getSettings();
        boolean autoExpands =
                !AUTO_EXPAND_DISABLED.equals(
                        Index.readOrRaw(SupportedSetting.AUTO_EXPAND_REPLICAS, current));
        for (String key : overrides.keySet()) {
            SupportedSetting setting = SupportedSetting.fromKey(key);
            // With auto-expand the index holds the replica count OpenSearch computed, not a setting.
            if (setting == null || (setting == SupportedSetting.NUMBER_OF_REPLICAS && autoExpands)) {
                continue;
            }
            String actual = Index.readOrRaw(setting, current);
            if (!setting.read(overrides).equals(actual)) {
                // The value as the index holds it. The one read is only for comparing.
                log.warn(
                        "Index [{}] exists with [{}] = [{}]. The override [{}] applies only to indices created from now on.",
                        writeIndex.getIndex().getName(),
                        key,
                        current.get(key, actual),
                        overrides.get(key));
            }
        }
    }

    /**
     * Reads a setting of an existing index. An index can hold a value the configuration file does not
     * accept, set by hand; it is then returned as it is stored.
     *
     * @param setting the setting to read.
     * @param settings the settings of the index.
     * @return the value of the setting.
     */
    private static String readOrRaw(SupportedSetting setting, Settings settings) {
        try {
            return setting.read(settings);
        } catch (IllegalArgumentException e) {
            return String.valueOf(settings.get(setting.key()));
        }
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
     * Sanitizes a template path to obtain the template name. Removes the "templates/" prefix and
     * converts remaining slashes to hyphens.
     *
     * @param templatePath the template path (e.g., "templates/streams/alerts")
     * @return the template name (e.g., "streams-alerts")
     */
    private String getTemplateName(String templatePath) {
        templatePath = templatePath.replaceFirst("^templates/", "");
        return templatePath.replace("/", "-");
    }

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
        String templateName = this.getTemplateName(template);

        try {
            // Read JSON index template
            ObjectMapper mapper = new ObjectMapper();
            IndexTemplate indexTemplate = this.loadTemplate(template);
            indexTemplate.validateSchemaVersions(templateName);

            // Create a V2 template (ComposableIndexTemplate)
            String indexMappings = mapper.writeValueAsString(indexTemplate.getMappings());
            CompressedXContent compressedMapping = new CompressedXContent(indexMappings);
            Settings settings = this.templateSettings(template, templateName, indexTemplate);
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
