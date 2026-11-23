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
import org.opensearch.action.admin.indices.delete.DeleteIndexRequest;

import com.wazuh.setup.settings.PluginSettings;

/**
 * Class to represent a Content index. Content indices hold the catalog content the Content Manager
 * downloads from CTI (IoCs, CVEs and the Engine ruleset: decoders, rules, KVDBs, integrations,
 * policies and filters).
 *
 * <p>A content index is alias-backed (see {@link AliasedIndex}): the Content Manager rebuilds the
 * content into the alternate {@code <name>-b} slot when the content source changes and swaps the
 * alias atomically.
 */
public class ContentIndex extends AliasedIndex {
    private static final Logger log = LogManager.getLogger(ContentIndex.class);

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
     * Every content index gets its own template, named after the alias.
     *
     * @param templatePath the template path.
     * @return the alias name plus {@code -template}.
     */
    @Override
    protected String templateName(String templatePath) {
        return this.index + "-template";
    }

    /**
     * Deletes a concrete index whose name equals the public alias name.
     *
     * <p>Such an index can only come from a write that reached the alias name before anything created
     * the alias, in which case OpenSearch auto-created it with dynamic mappings: every keyword the
     * schema declares became a text field, which cannot be aggregated or sorted on. The content it
     * holds is re-downloaded from CTI.
     *
     * @param alias the public alias name.
     * @return false: the name is free and {@code <name>-a} still has to be created with the alias.
     */
    @Override
    protected boolean onConcreteIndexAtAliasName(String alias) {
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
        return false;
    }
}
