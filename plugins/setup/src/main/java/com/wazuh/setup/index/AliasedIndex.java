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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.alias.Alias;
import org.opensearch.action.admin.indices.alias.IndicesAliasesRequest;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;

import java.util.List;

import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.settings.PluginSettings;

/**
 * An index that is never addressed by its own name. The concrete index is created as {@code
 * <name>-a} and a write alias named {@code <name>} points at it, so the content can be rebuilt into
 * the alternate {@code <name>-b} slot and the alias swapped atomically, without exposing a
 * partially populated index or blocking writes for the duration of the rebuild.
 *
 * <p>Once the alias exists the topology is in place and nothing more is done, whichever physical
 * index it points at. It is not always {@code -a}: a blue/green swap moves the alias to the
 * alternate slot and then deletes the one it came from, so a cluster that has been rebuilt sits on
 * {@code <name>-b} with no {@code <name>-a} at all. Creating {@code <name>-a} with the alias then
 * would ask OpenSearch for a second write index on the same alias, which fails with {@code alias
 * [...] has more than one write index}. That aborts {@code SetupPlugin}'s initialization loop, so
 * every index registered after this one is skipped and the readiness marker is set to failed, on
 * every restart.
 *
 * <p>A concrete index whose name is the alias name cannot coexist with the alias. What to do with
 * one is up to the subclass ({@link #onConcreteIndexAtAliasName(String)}): content indices delete
 * it, state indices migrate it.
 */
public abstract class AliasedIndex extends WazuhIndex {
    private static final Logger log = LogManager.getLogger(AliasedIndex.class);

    /** Suffix of the concrete index this class creates and points the public alias at. */
    public static final String SUFFIX_A = "-a";

    /**
     * Constructor.
     *
     * @param index public alias name. The concrete index is this name plus {@link #SUFFIX_A}.
     * @param template path to the index template resource (without the .json extension).
     */
    AliasedIndex(String index, String template) {
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
     * Rewrites the index patterns to {@code <name>*} so the template applies to the live {@code -a}
     * index, to the {@code -b} slot a rebuild creates and, as a last line of defence, to the alias
     * name itself, whatever pattern the shipped JSON declares.
     *
     * @param indexTemplate the parsed template, modified in place.
     */
    @Override
    protected void customizeTemplate(IndexTemplate indexTemplate) {
        indexTemplate.setIndexPatterns(List.of(this.index + "*"));
    }

    /**
     * Overrides {@link Index#createIndex(String)} to create the concrete {@code <name>-a} index with
     * the public alias {@code <name>} pointing at it.
     *
     * @param index name of the public alias. The concrete index created is this name plus {@link
     *     #SUFFIX_A}.
     */
    @Override
    public void createIndex(String index) {
        String physicalName = this.getPhysicalName();
        try {
            if (this.clusterService.state().metadata().hasIndex(index)
                    && this.onConcreteIndexAtAliasName(index)) {
                return;
            }

            if (this.aliasExists(index)) {
                log.debug("Alias {} already exists. Skipping.", index);
                return;
            }

            if (this.indexExists(physicalName)) {
                this.addAlias(index, physicalName);
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
            if (this.indexCreationAttempts
                    >= PluginSettings.getMaxRetries(this.clusterService.getSettings())) {
                log.error(
                        "Initialization of index [{}] finally failed. The node will shut down.", physicalName);
                throw e;
            }
            log.warn("Operation to create the index [{}] timed out. Retrying...", physicalName);
            this.indexCreationAttempts++;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createIndex(index);
        }
    }

    /**
     * Handles a concrete index whose name equals the public alias name. It occupies the name the
     * alias needs, so it must be gone, one way or another, when this method returns.
     *
     * @param alias the public alias name, which is also the name of the concrete index.
     * @return true when the handling left the alias in place, so there is nothing more to create;
     *     false when the name is now free and the concrete index and the alias still have to be
     *     created.
     */
    protected abstract boolean onConcreteIndexAtAliasName(String alias);

    /**
     * Returns whether the public alias exists, whichever concrete index it points at.
     *
     * @param alias the public alias name.
     * @return true if the alias exists on the cluster, false otherwise.
     */
    protected boolean aliasExists(String alias) {
        return this.clusterService.state().metadata().hasAlias(alias);
    }

    /**
     * Points the public alias at the concrete index. Only called when the concrete index exists and
     * the alias does not, so there is no write index to conflict with.
     *
     * @param alias the public alias name.
     * @param physicalName the concrete index the alias must point at.
     */
    private void addAlias(String alias, String physicalName) {
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
