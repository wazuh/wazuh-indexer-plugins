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
import org.opensearch.action.DocWriteRequest;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.metadata.IndexAbstraction;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.core.xcontent.MediaTypeRegistry;
import org.opensearch.index.engine.VersionConflictEngineException;

import java.time.Instant;
import java.util.Map;

import com.wazuh.setup.settings.PluginSettings;

/**
 * Base class for indices managed by an ISM policy whose backing index needs to be explicitly
 * registered with the ISM coordinator. Subclasses implement {@link #resolveBackingIndexName()} to
 * provide the name of the index to register (typically the write target of a data stream or write
 * alias).
 *
 * <p>The shared {@link #registerWithISM()} writes a {@code ManagedIndexConfig} document directly
 * into {@code .opendistro-ism-config}, keyed by the backing index UUID, equivalent to {@code POST
 * _plugins/_ism/add/<index>}. This is required because ISM policies indexed directly (i.e.,
 * bypassing the ISM REST API) don't register their {@code ism_template} patterns with the ISM
 * coordinator cache, so the backing indices are not auto-detected.
 */
public abstract class IsmManagedIndex extends WazuhIndex {
    private static final Logger log = LogManager.getLogger(IsmManagedIndex.class);

    private static final String POLICY_ID_SETTING = "index.plugins.index_state_management.policy_id";

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template path to the index template resource (without .json extension).
     */
    protected IsmManagedIndex(String index, String template) {
        super(index, template);
    }

    /**
     * Returns the name of the backing index whose lifecycle should be registered with ISM. Subclasses
     * look this up from cluster state — typically the write index of a data stream or the write
     * target of an alias. Return {@code null} to skip registration (e.g., when the source entity
     * doesn't exist yet).
     *
     * @return the backing index name to register, or {@code null} to skip.
     */
    protected abstract String resolveBackingIndexName();

    /**
     * Returns true if {@code indexName} is one of this instance's backing indices according to the
     * given cluster state — used by {@link IsmRolloverListener} to dispatch rollover-target enrolment
     * to the owning instance. Works for both data-stream backings and write-alias backings because
     * both expose their member indices via {@link IndexAbstraction}.
     *
     * @param indexName candidate backing index name (e.g., from {@code event.indicesCreated()}).
     * @param state cluster state snapshot the listener was invoked with.
     * @return true if this {@code IsmManagedIndex} owns the candidate.
     */
    protected boolean ownsBackingIndex(String indexName, ClusterState state) {
        IndexAbstraction abs = state.metadata().getIndicesLookup().get(this.index);
        if (abs == null) {
            return false;
        }
        return abs.getIndices().stream().anyMatch(im -> im.getIndex().getName().equals(indexName));
    }

    /**
     * Adds an ISM registration pass after the standard {@code createTemplate} + {@code createIndex}
     * sequence inherited from {@link Index}.
     */
    @Override
    public void initialize() {
        this.createTemplate(this.template);
        this.createIndex(this.index);
        this.registerWithISM();
    }

    /**
     * Registers the backing index resolved by {@link #resolveBackingIndexName()} with ISM by writing
     * a {@code ManagedIndexConfig} document directly to {@code .opendistro-ism-config}. Idempotent: a
     * pre-existing doc is detected and the write is skipped; concurrent writers race-lose via {@code
     * OpType.CREATE} → {@link VersionConflictEngineException}.
     */
    protected final void registerWithISM() {
        String backingIndex = this.resolveBackingIndexName();
        if (backingIndex == null) {
            return;
        }

        IndexMetadata indexMetadata = this.clusterService.state().metadata().index(backingIndex);
        if (indexMetadata == null) {
            log.warn(
                    "Index metadata for [{}] not found in cluster state. Skipping ISM registration.",
                    backingIndex);
            return;
        }

        String policyId = indexMetadata.getSettings().get(POLICY_ID_SETTING);
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
}
