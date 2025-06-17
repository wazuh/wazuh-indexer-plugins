/*
 * Copyright (C) 2024, Wazuh Inc.
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
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.core.xcontent.MediaTypeRegistry;

import java.io.IOException;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;

/** Class to manage the Command Manager index and index template. */
public class IndexStateManagement extends Index {

    private static final Logger log = LogManager.getLogger(IndexStateManagement.class);
    private static final String INDEX = ".opendistro-ism-config";
    private static final String TEMPLATE = "opendistro-ism-config.json";

    private IndexStateManagement() {
        super(INDEX, TEMPLATE);
    }

    private void indexPolicy(String policy) {
        try {
            Map<String, Object> policy;
            policy = this.indexUtils.fromFile(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID + ".json");

            IndexRequest indexRequest =
                    new IndexRequest(INDEX)
                            .index(INDEX)
                            .id(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID)
                            .source(policy, MediaTypeRegistry.JSON);

            client.index(indexRequest).actionGet(SetupPlugin.TIMEOUT);
            log.info("Indexed Wazuh rollover policy into {} index", INDEX);
        } catch (IOException e) {
            log.error("Failed to load the Wazuh rollover policy from file: {}", e.getMessage());
        } catch (ResourceAlreadyExistsException e) {
            log.error("Policy already exists, skipping creation: {}", e.getMessage());
        }
    }

    @Override
    public void initialize() {
        if (this.indexExists(INDEX)) {
            log.info("{} index exists, skipping", INDEX);
            return;
        }
        Map<String, Object> template;
        log.info("Attempting to create {} index", INDEX);
        try {
            template = this.indexUtils.fromFile(TEMPLATE);
            this.client
                    .admin()
                    .indices()
                    .create(
                            new CreateIndexRequest(INDEX)
                                    .mapping(this.indexUtils.get(template, "mappings"))
                                    .settings(this.indexUtils.get(template, "settings")))
                    .actionGet(SetupPlugin.TIMEOUT);
            log.info("Successfully created {} index", INDEX);
        } catch (IOException e) {
            log.error("Failed loading ISM index from file: {}", e.getMessage());
        } catch (ResourceAlreadyExistsException e) {
            log.error("Index already exists, skipping creation: {}", e.getMessage());
        }
        indexPolicy(SetupPlugin.WAZUH_ALERTS_ROLLOVER_POLICY_ID);
    }
}
