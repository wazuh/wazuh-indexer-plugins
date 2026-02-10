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
package com.wazuh.contentmanager.cti.catalog.service;

import com.google.gson.JsonObject;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.env.Environment;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Snapshot service for IoC content. Overrides index resolution to always target the IoC index,
 * rather than determining the index from each payload's type field.
 */
public class IocSnapshotServiceImpl extends SnapshotServiceImpl {

    /**
     * Constructs a new IocSnapshotServiceImpl.
     *
     * @param context The context of the snapshot.
     * @param consumer The consumer identifier.
     * @param indicesMap A map of content types to their corresponding ContentIndex.
     * @param consumersIndex The consumers index to update consumer state.
     * @param environment The OpenSearch environment.
     */
    public IocSnapshotServiceImpl(
            String context,
            String consumer,
            Map<String, ContentIndex> indicesMap,
            ConsumersIndex consumersIndex,
            Environment environment) {
        super(context, consumer, indicesMap, consumersIndex, environment);
    }

    @Override
    protected ContentIndex resolveIndex(JsonObject payload) {
        return this.indicesMap.get(Constants.KEY_IOCS);
    }

    @Override
    protected void setIndexRequestId(JsonObject processedPayload, IndexRequest indexRequest) {
        if (processedPayload.has(Constants.KEY_ID)) {
            String id = processedPayload.get(Constants.KEY_ID).getAsString();
            indexRequest.id(id);
        }
    }
}
