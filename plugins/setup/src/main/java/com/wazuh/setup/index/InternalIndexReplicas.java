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

import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.regex.Regex;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.shard.IndexSettingProvider;

import java.util.List;

/**
 * Creates the ISM history indices and the backing indices of the {@code security-auditlogs} data
 * stream with {@code index.auto_expand_replicas: 0-1}, as the Wazuh indices. Their plugins create
 * them with a fixed replica count. A template or create request that sets the setting itself wins.
 */
public class InternalIndexReplicas implements IndexSettingProvider {

    /** Replica range of the Wazuh indices. */
    public static final String AUTO_EXPAND_REPLICAS = "0-1";

    /** Indices that upstream plugins create with a fixed replica count. */
    public static final List<String> PATTERNS =
            List.of(".opendistro-ism-managed-index-history-*", ".ds-security-auditlogs-*");

    private static final Settings SETTINGS =
            Settings.builder()
                    .put(IndexMetadata.SETTING_AUTO_EXPAND_REPLICAS, AUTO_EXPAND_REPLICAS)
                    .build();

    @Override
    public Settings getAdditionalIndexSettings(
            String indexName, boolean isDataStreamIndex, Settings templateAndRequestSettings) {
        return Regex.simpleMatch(PATTERNS, indexName) ? SETTINGS : Settings.EMPTY;
    }
}
