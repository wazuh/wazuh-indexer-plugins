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
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutComposableIndexTemplateAction;
import org.opensearch.cluster.metadata.ComposableIndexTemplate;
import org.opensearch.cluster.metadata.Template;
import org.opensearch.common.compress.CompressedXContent;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.indexmanagement.indexstatemanagement.transport.action.addpolicy.AddPolicyAction;
import org.opensearch.indexmanagement.indexstatemanagement.transport.action.addpolicy.AddPolicyRequest;

import java.io.IOException;
import java.io.InputStream;
import java.util.List;
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
 *
 * <p><b>ISM enrolment note:</b> ISM does not auto-enrol {@code .ds-}-prefixed regular indices via
 * its coordinator sweep (verified empirically: even with the {@code policy_id} setting present on
 * the index, a sweep leaves it unmanaged). When a {@code policyId} is configured, this class
 * dispatches ISM's {@link AddPolicyAction} transport action after the backing index is created —
 * the same code path the {@code POST /_plugins/_ism/add/<index>} REST endpoint uses.
 */
public class AliasedIndex extends WazuhIndex {
    private static final Logger log = LogManager.getLogger(AliasedIndex.class);

    private static final String BACKING_INDEX_PREFIX = ".ds-";
    private static final String BACKING_INDEX_SUFFIX = "-000001";

    /**
     * Default index type understood by ISM's {@code IndexMetadataProvider}. The literal string is
     * {@code "_default"} (with underscore) — using {@code "default"} causes ISM to throw {@code
     * "Index type [type=default] was not recognized"}.
     */
    private static final String DEFAULT_INDEX_TYPE = "_default";

    private final String policyId;

    /**
     * Constructor without an explicit ISM policy. The backing index is created with no policy
     * attached.
     *
     * @param alias visible alias name (e.g., "wazuh-findings-v5-security"). Also used as the rollover
     *     alias.
     * @param template path to the index template resource (without .json extension).
     */
    public AliasedIndex(String alias, String template) {
        this(alias, template, null);
    }

    /**
     * Constructor with an explicit ISM policy. After the backing index is created, the policy is
     * attached via ISM's {@link AddPolicyAction} transport action.
     *
     * @param alias visible alias name. Also used as the rollover alias.
     * @param template path to the index template resource (without .json extension).
     * @param policyId ISM policy id to attach to the backing index, or null to skip the attach.
     */
    public AliasedIndex(String alias, String template, String policyId) {
        super(alias, template);
        this.policyId = policyId;
    }

    /**
     * Creates the composable index template. Mirrors {@link StreamIndex#createTemplate(String)} but
     * strips any {@code data_stream} block so the template materializes as a regular index template.
     *
     * @param template path to the index template resource (without .json extension).
     */
    @Override
    public void createTemplate(String template) {
        String templateName = this.index + "-template";

        try {
            ObjectMapper mapper = new ObjectMapper();
            InputStream is = this.getClass().getClassLoader().getResourceAsStream(template + ".json");
            IndexTemplate indexTemplate = mapper.readValue(is, IndexTemplate.class);

            // Restrict the template to this specific index/alias pattern and rewrite the rollover alias.
            indexTemplate.setIndexPatterns(List.of(BACKING_INDEX_PREFIX + this.index + "*"));
            Map<String, Object> settingsMap = indexTemplate.getSettings();
            if (settingsMap != null
                    && settingsMap.containsKey("plugins.index_state_management.rollover_alias")) {
                settingsMap.put("plugins.index_state_management.rollover_alias", this.index);
            }

            String indexMappings = mapper.writeValueAsString(indexTemplate.getMappings());
            CompressedXContent compressedMapping = new CompressedXContent(indexMappings);
            Settings settings = Settings.builder().loadFromMap(indexTemplate.getSettings()).build();

            // Build the composable template directly (without dataStreamTemplate) so this works even
            // when the source template still carries a "data_stream" block.
            ComposableIndexTemplate composableTemplate =
                    new ComposableIndexTemplate(
                            indexTemplate.getIndexPatterns(),
                            new Template(settings, compressedMapping, null),
                            null,
                            indexTemplate.getPriority(),
                            null,
                            null,
                            null);

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
     * Creates the initial hidden backing index with the visible write alias. Skips creation if the
     * alias already exists. When a {@code policyId} is configured, attaches the policy via ISM's
     * {@link AddPolicyAction} after the create succeeds.
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
                            .settings(Settings.builder().put("index.hidden", true))
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

            this.attachPolicy(backingIndex);
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
     * Dispatches ISM's {@link AddPolicyAction} to attach {@link #policyId} to the given backing
     * index. Best-effort: a failure is logged and execution continues — the index is still functional
     * and an operator can re-run {@code POST /_plugins/_ism/add/<index>} by hand.
     *
     * @param backingIndex name of the backing index to enrol.
     */
    void attachPolicy(String backingIndex) {
        if (this.policyId == null) {
            return;
        }
        AddPolicyRequest request =
                new AddPolicyRequest(List.of(backingIndex), this.policyId, DEFAULT_INDEX_TYPE);
        this.client.execute(
                AddPolicyAction.Companion.getINSTANCE(),
                request,
                ActionListener.wrap(
                        resp ->
                                log.info(
                                        "ISM policy [{}] attached to [{}] (updated: {}, failed: {})",
                                        this.policyId,
                                        backingIndex,
                                        resp.getUpdated(),
                                        resp.getFailedIndices().size()),
                        err ->
                                log.error(
                                        "Failed to attach ISM policy [{}] to [{}]", this.policyId, backingIndex, err)));
    }
}
