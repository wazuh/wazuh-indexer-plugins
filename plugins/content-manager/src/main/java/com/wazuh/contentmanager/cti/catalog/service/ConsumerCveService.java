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

import org.opensearch.env.Environment;
import org.opensearch.transport.client.Client;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Handles synchronization logic for the CVE consumer. Processes CVEs and handles post-sync
 * operations.
 */
public class ConsumerCveService extends AbstractConsumerService {

    /**
     * Constructs a new ConsumerCveService.
     *
     * @param client The OpenSearch client.
     * @param consumersIndex The consumers index wrapper.
     * @param environment The OpenSearch environment settings.
     */
    public ConsumerCveService(Client client, ConsumersIndex consumersIndex, Environment environment) {
        super(client, consumersIndex, environment);
    }

    @Override
    protected String getConsumerType() {
        return "cti:catalog:consumer:vulnerabilities";
    }

    @Override
    protected String getCustomCatalogUri() {
        return PluginSettings.getInstance().getCatalogVulnerabilities();
    }

    @Override
    protected String getSnapshotFilename() {
        return Constants.CVE_SNAPSHOT_FILENAME;
    }

    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new HashMap<>();
        mappings.put(Constants.KEY_CVES, "/mappings/cti-cve-mappings.json");
        return mappings;
    }

    @Override
    public void onSyncComplete(boolean isUpdated) {
        if (isUpdated) {
            this.refreshIndices(Constants.INDEX_CVES);
        }
    }
}
