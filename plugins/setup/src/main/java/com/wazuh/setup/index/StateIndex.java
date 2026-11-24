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
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;
import org.opensearch.action.admin.indices.refresh.RefreshRequest;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.search.builder.SearchSourceBuilder;

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
 */
public class StateIndex extends AliasedIndex {
    private static final Logger log = LogManager.getLogger(StateIndex.class);

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
     * A concrete index named after the alias is not expected: the plugin creates the alias before any
     * writer can reach the name, and the user the Wazuh server writes with cannot create indices, so
     * no write auto-creates one. An empty one is deleted so the alias can take the name. One that
     * holds documents is the state of every agent, which nothing re-sends, so it is kept and the
     * initialization fails naming it.
     *
     * @param alias the public alias name, which is also the name of the concrete index.
     * @throws IllegalStateException if the concrete index holds documents.
     */
    @Override
    protected void onConcreteIndexAtAliasName(String alias) {
        long timeout = PluginSettings.getTimeout(this.clusterService.getSettings());
        long documents = this.count(alias, timeout);
        if (documents > 0) {
            throw new IllegalStateException(
                    "["
                            + alias
                            + "] is a concrete index holding "
                            + documents
                            + " documents, but the name is reserved for the alias of ["
                            + this.getPhysicalName()
                            + "]. It is kept; delete it or reindex it by hand to let the alias be created");
        }
        log.warn(
                "Found an empty concrete index named [{}], which is the name reserved for the public alias. "
                        + "Deleting it so the alias can be created.",
                alias);
        this.client.admin().indices().delete(new DeleteIndexRequest(alias)).actionGet(timeout);
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
}
