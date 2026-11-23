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
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.admin.indices.settings.put.UpdateSettingsRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.reindex.BulkByScrollResponse;
import org.opensearch.index.reindex.ReindexAction;
import org.opensearch.index.reindex.ReindexRequest;
import org.opensearch.search.builder.SearchSourceBuilder;

import java.io.IOException;
import java.util.Map;

import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Class to represent a Stateful index. Stateful indices represent the most recent information of a
 * subject (active vulnerabilities, installed packages, open ports, ...). These indices are
 * different of Stream indices as they do not contain timestamps. The information is not based on
 * time, as they always represent the most recent state.
 *
 * <p>A state index is alias-backed (see {@link AliasedIndex}), so a breaking schema change can be
 * applied by rebuilding it into the alternate slot and swapping the alias, instead of deleting and
 * reindexing the only copy of the data while writes are blocked.
 *
 * <p>A cluster created before state indices were alias-backed has a concrete index named {@code
 * <name>}. It is migrated once, at boot, by {@link #migrate(String)}.
 */
public class StateIndex extends AliasedIndex {
    private static final Logger log = LogManager.getLogger(StateIndex.class);

    /** Migration step recorded once the {@code <name>-a} index exists. */
    public static final String STEP_TARGET_CREATED = "alias_migration_target_created";

    /** Migration step recorded once every document has been copied and the copy verified. */
    public static final String STEP_COPIED = "alias_migration_copied";

    /**
     * Constructor.
     *
     * @param index index name, which becomes the public alias. The concrete index is this name plus
     *     {@link #SUFFIX_A}.
     * @param template index template name.
     */
    public StateIndex(String index, String template) {
        super(index, template);
    }

    /**
     * A concrete index named after the alias holds the state written before this version, so it is
     * migrated rather than deleted.
     *
     * @param alias the public alias name, which is also the name of the concrete index.
     * @return true: the migration ends with the alias in place.
     */
    @Override
    protected boolean onConcreteIndexAtAliasName(String alias) {
        this.migrate(alias);
        return true;
    }

    /**
     * Migrates a concrete index named {@code <name>} to the alias topology, in four steps:
     *
     * <ol>
     *   <li>Create {@code <name>-a} from the shipped template.
     *   <li>Block writes on {@code <name>}, so the copy is exact and can be verified.
     *   <li>Copy every document to {@code <name>-a} and verify that both hold the same number.
     *   <li>Delete {@code <name>} and create the alias in a single atomic request, so no write can
     *       auto-create a concrete index under the alias name in between.
     * </ol>
     *
     * <p>The concrete index is never deleted before the copy is verified complete. Each step is
     * recorded in the index's record in {@code .wazuh-setup-status}, so a migration interrupted by a
     * restart resumes after the last step it completed: the target is not created twice, and a
     * verified copy is not repeated. A copy recorded but found incomplete is run again.
     *
     * <p>Writes to {@code <name>} are rejected from step 2 until the alias exists. This migration
     * runs once, on the first boot after the upgrade from a version that wrote the state indices by
     * name.
     *
     * @param alias the public alias name, which is also the name of the concrete index.
     * @throws IllegalStateException if the copy cannot be verified complete or a step fails.
     */
    void migrate(String alias) {
        String physical = this.getPhysicalName();
        long timeout = PluginSettings.getTimeout(this.clusterService.getSettings());
        String step = this.recordedStep(alias);
        log.warn(
                "Index [{}] is a concrete index, created before state indices were alias-backed. "
                        + "Migrating it to [{}] behind the alias [{}]{}.",
                alias,
                physical,
                alias,
                step == null ? "" : ", resuming after step [" + step + "]");

        // 1. The target, from the shipped template.
        if (!this.indexExists(physical)) {
            this.client.admin().indices().create(new CreateIndexRequest(physical)).actionGet(timeout);
            log.info("Index [{}] created as the migration target of [{}].", physical, alias);
        }
        if (step == null) {
            step = this.recordStep(alias, STEP_TARGET_CREATED);
        }

        // 2. No more writes to the source, so the copy is exact.
        this.client
                .admin()
                .indices()
                .updateSettings(
                        new UpdateSettingsRequest(alias)
                                .settings(Settings.builder().put(IndexMetadata.SETTING_BLOCKS_WRITE, true)))
                .actionGet(timeout);

        // 3. The copy, verified by document count. A verified copy is not repeated on resume, unless
        // the counts no longer match.
        if (!STEP_COPIED.equals(step)) {
            this.copy(alias, physical, timeout);
        }
        long source = this.count(alias, timeout);
        long target = this.count(physical, timeout);
        if (source != target && STEP_COPIED.equals(step)) {
            log.warn(
                    "Copy of [{}] to [{}] was recorded complete but holds {} of {} documents. Copying again.",
                    alias,
                    physical,
                    target,
                    source);
            this.copy(alias, physical, timeout);
            target = this.count(physical, timeout);
        }
        if (source != target) {
            throw new IllegalStateException(
                    "migration of ["
                            + alias
                            + "] to ["
                            + physical
                            + "] copied "
                            + target
                            + " of "
                            + source
                            + " documents; the concrete index is kept");
        }
        if (!STEP_COPIED.equals(step)) {
            step = this.recordStep(alias, STEP_COPIED);
        }

        // 4. The swap: the concrete index goes and the alias takes its name, atomically.
        IndicesAliasesRequest swap =
                new IndicesAliasesRequest()
                        .addAliasAction(IndicesAliasesRequest.AliasActions.removeIndex().index(alias))
                        .addAliasAction(
                                IndicesAliasesRequest.AliasActions.add()
                                        .index(physical)
                                        .alias(alias)
                                        .writeIndex(true));
        this.client.admin().indices().aliases(swap).actionGet(timeout);
        log.info(
                "Index [{}] migrated: {} documents now live in [{}] behind the alias [{}].",
                alias,
                target,
                physical,
                alias);
    }

    /**
     * Copies every document of the source index to the destination, refreshing the destination at the
     * end.
     *
     * @param source the index to copy from.
     * @param destination the index to copy to.
     * @param timeout how long to wait for the copy, in milliseconds.
     * @throws IllegalStateException if the copy reports failures or times out.
     */
    private void copy(String source, String destination, long timeout) {
        ReindexRequest request = new ReindexRequest();
        request.setSourceIndices(source);
        request.setDestIndex(destination);
        request.setRefresh(true);
        BulkByScrollResponse response =
                this.client.execute(ReindexAction.INSTANCE, request).actionGet(timeout);
        if (!response.getBulkFailures().isEmpty()
                || !response.getSearchFailures().isEmpty()
                || response.isTimedOut()) {
            throw new IllegalStateException(
                    "copying ["
                            + source
                            + "] to ["
                            + destination
                            + "] failed ("
                            + response.getBulkFailures().size()
                            + " bulk failures, "
                            + response.getSearchFailures().size()
                            + " search failures, timed out: "
                            + response.isTimedOut()
                            + ")"
                            + (response.getBulkFailures().isEmpty()
                                    ? ""
                                    : ", first: " + response.getBulkFailures().get(0).getMessage()));
        }
        log.info(
                "Copied {} documents from [{}] to [{}].",
                response.getCreated() + response.getUpdated(),
                source,
                destination);
    }

    /**
     * Counts the documents of an index, after refreshing it.
     *
     * @param index the index.
     * @param timeout how long to wait for each request, in milliseconds.
     * @return the number of documents.
     */
    private long count(String index, long timeout) {
        this.client.admin().indices().refresh(new RefreshRequest(index)).actionGet(timeout);
        SearchResponse response =
                this.client
                        .search(
                                new SearchRequest(index)
                                        .source(new SearchSourceBuilder().size(0).trackTotalHits(true)))
                        .actionGet(timeout);
        return response.getHits().getTotalHits().value();
    }

    /**
     * Returns the migration step recorded for the index on a previous boot, if any.
     *
     * @param alias the index name.
     * @return the step, or null when none is recorded or no status index is available.
     */
    private String recordedStep(String alias) {
        if (this.statusIndex == null) {
            return null;
        }
        return this.statusIndex.getIndexRecord(alias).map(IndexRecord::step).orElse(null);
    }

    /**
     * Records a completed migration step in the index's record, with the versions the concrete index
     * and the shipped template carry.
     *
     * @param alias the index name.
     * @param step the step just completed.
     * @return the step, for chaining.
     */
    private String recordStep(String alias, String step) {
        if (this.statusIndex == null) {
            log.debug("No status index to record step [{}] of [{}] in.", step, alias);
            return step;
        }
        try {
            Map<String, Object> shipped = this.loadTemplate().getSchemaVersions();
            long shippedVersion = ((Number) shipped.get(IndexTemplate.SCHEMA_VERSION_KEY)).longValue();
            long compatVersion = ((Number) shipped.get(IndexTemplate.COMPAT_VERSION_KEY)).longValue();
            this.statusIndex.putIndexRecord(
                    IndexRecord.of(
                            alias, this.getInstalledSchemaVersion(), shippedVersion, compatVersion, step));
        } catch (IOException e) {
            throw new IllegalStateException(
                    "cannot read the template of [" + alias + "] to record step [" + step + "]", e);
        }
        return step;
    }
}
