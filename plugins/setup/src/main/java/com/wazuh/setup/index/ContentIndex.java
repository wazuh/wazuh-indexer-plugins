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
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;

import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Class to represent a Content index. Content indices hold the catalog content the Content Manager
 * downloads from CTI (IoCs, CVEs and the Engine ruleset: decoders, rules, KVDBs, integrations,
 * policies and filters).
 *
 * <p>Unlike {@link StateIndex} and {@link StreamIndex}, a content index is not addressed by its own
 * name. The concrete index is created as {@code <name>-a} and a write alias named {@code <name>}
 * points at it, so the Content Manager can rebuild the content into the alternate {@code <name>-b}
 * slot and swap the alias atomically without exposing a partially populated index.
 */
public class ContentIndex extends WazuhIndex {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

    /** Suffix of the concrete index this class creates and points the public alias at. */
    public static final String SUFFIX_A = "-a";

    /**
     * Constructor.
     *
     * @param index public alias name (e.g., "wazuh-threatintel-enrichments"). The concrete index is
     *     this name plus {@link #SUFFIX_A}.
     * @param template path to the index template resource (without the .json extension).
     */
    public ContentIndex(String index, String template) {
        super(index, template);
    }

    /**
     * Returns the name of the concrete index backing the public alias.
     *
     * @return the alias name plus {@link #SUFFIX_A}.
     */
    public String getPhysicalName() {
        return this.index + SUFFIX_A;
    }

    /**
     * Overrides createTemplate so the index patterns cover every concrete index behind the alias.
     *
     * <p>The shipped JSON declares whichever pattern the schema generator produced, which does not
     * necessarily match the suffixed names. Rewriting it to {@code <name>*} makes the template apply
     * to the live {@code -a} index and to the {@code -b} shadow slot the Content Manager creates
     * during a blue/green swap.
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

            // Dynamically set the index patterns to match every concrete index behind the alias
            indexTemplate.setIndexPatterns(List.of(this.index + "*"));

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
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index template also failed. Original exception is
            // rethrown.
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
     * Overrides {@link Index#createIndex(String)} to create the concrete {@code <name>-a} index with
     * the public alias {@code <name>} pointing at it.
     *
     * <p>A concrete index whose name is the alias name is removed first. Such an index can only come
     * from a write that reached the alias name before anything created the alias, in which case
     * OpenSearch auto-created it with dynamic mappings: every keyword the schema declares became a
     * text field, which cannot be aggregated or sorted on. It also occupies the alias's name, so the
     * alias cannot be created until it is gone. The content it holds is re-downloaded from CTI.
     *
     * @param index name of the public alias. The concrete index created is this name plus {@link
     *     #SUFFIX_A}.
     */
    @Override
    public void createIndex(String index) {
        String physicalName = index + SUFFIX_A;
        try {
            this.deleteSquatterIndex(index);

            if (this.indexExists(physicalName)) {
                this.ensureAlias(index, physicalName);
                return;
            }

            CreateIndexRequest request =
                    new CreateIndexRequest(physicalName).alias(new Alias(index).writeIndex(true));
            CreateIndexResponse response =
                    this.client
                            .admin()
                            .indices()
                            .create(request)
                            .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
            log.info(
                    "Index created successfully: {} {} (alias {})",
                    response.index(),
                    response.isAcknowledged(),
                    index);
        } catch (ResourceAlreadyExistsException e) {
            log.debug("Index {} already exists. Skipping.", physicalName);
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index also failed. Original exception is rethrown.
            if (!this.retry_index_creation) {
                log.error(
                        "Initialization of index [{}] finally failed. The node will shut down.", physicalName);
                throw e;
            }
            log.warn("Operation to create the index [{}] timed out. Retrying...", physicalName);
            this.retry_index_creation = false;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createIndex(index);
        }
    }

    /**
     * Deletes a concrete index whose name equals the public alias name, if one exists.
     *
     * @param alias the public alias name.
     */
    private void deleteSquatterIndex(String alias) {
        if (!this.clusterService.state().metadata().hasIndex(alias)) {
            return;
        }
        log.warn(
                "Found a concrete index named [{}], which is the name reserved for the public alias. "
                        + "It was auto-created with dynamic mappings and its fields cannot be aggregated on. "
                        + "Deleting it so the alias can be created; its content is downloaded again.",
                alias);
        this.client
                .admin()
                .indices()
                .delete(new DeleteIndexRequest(alias))
                .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
    }

    /**
     * Points the public alias at the concrete index when the concrete index already exists without
     * it. Nothing is done when the alias is already present.
     *
     * @param alias the public alias name.
     * @param physicalName the concrete index the alias must point at.
     */
    private void ensureAlias(String alias, String physicalName) {
        if (this.clusterService.state().metadata().hasAlias(alias)) {
            log.debug("Index {} and its alias {} already exist. Skipping.", physicalName, alias);
            return;
        }
        log.info("Index {} exists without its alias {}. Adding it.", physicalName, alias);
        IndicesAliasesRequest request =
                new IndicesAliasesRequest()
                        .addAliasAction(
                                IndicesAliasesRequest.AliasActions.add()
                                        .index(physicalName)
                                        .alias(alias)
                                        .writeIndex(true));
        this.client
                .admin()
                .indices()
                .aliases(request)
                .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
    }
}
