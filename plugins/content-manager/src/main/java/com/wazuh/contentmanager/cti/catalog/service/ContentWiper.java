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
package com.wazuh.contentmanager.cti.catalog.service;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;

/**
 * Empties a consumer's content before a snapshot is loaded over it.
 *
 * <p>What "empty" means is not the same for every consumer, and deciding it inside the snapshot
 * service is what let the two load paths drift apart. The remote load was changed to delete only
 * the Standard space, so that the Draft, Test and Custom spaces and the user overrides registry
 * survive a resync; the load from a snapshot file kept deleting the indices outright and took all
 * of that with them. Handing the snapshot service a wiper keeps one definition per consumer, used
 * by both paths, instead of two that can drift again.
 *
 * <p>A wiper says whether it emptied the content, and that is not a detail the caller may ignore.
 * Ruleset resources reference each other -- a policy names integrations, an integration names
 * rules, decoders and KVDBs -- so documents left behind by a wipe that failed mix with the ones the
 * snapshot brings and produce a ruleset the Engine rejects. A load therefore stops when its wiper
 * says no. That does not make what is left behind consistent, see {@link StandardSpaceWiper}; it
 * keeps a snapshot from being written on top of it.
 *
 * <p>How much that answer is worth depends on the wiper. {@link #clearingIndices} reports success
 * either way, because the clear it delegates to swallows its own failures; the consumers that use
 * it hold nothing but CTI content, so an index left standing costs them nothing that the next load
 * does not put right. {@link StandardSpaceWiper} is the one whose answer carries weight, and its
 * own javadoc says how far it reaches.
 */
@FunctionalInterface
public interface ContentWiper {

    /**
     * Empties the content a snapshot is about to replace.
     *
     * @return {@code true} when the content is empty and the snapshot may be loaded over it, {@code
     *     false} when it is not, in which case the caller must not load.
     */
    boolean wipe();

    /**
     * A wiper that does nothing, for a load into the staging indices of a swap. Those indices are
     * created empty immediately before the load, so there is nothing to remove, and emptying them
     * again through {@link ContentIndex#clear()} would recreate them as ordinary indices: visible
     * instead of hidden, and carrying the public alias of the content that is still live.
     *
     * @return the wiper.
     */
    static ContentWiper none() {
        return () -> true;
    }

    /**
     * A wiper that deletes and recreates every index of the consumer, for content that is not divided
     * into spaces. The IoC and CVE consumers own their indices whole: everything in them comes from
     * CTI, so replacing the index is both correct and cheaper than deleting documents.
     *
     * @param indices the consumer's content indices, keyed by type.
     * @return the wiper.
     */
    static ContentWiper clearingIndices(Map<String, ContentIndex> indices) {
        return () -> {
            indices.values().forEach(ContentIndex::clear);
            return true;
        };
    }
}
