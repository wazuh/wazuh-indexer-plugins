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
import org.opensearch.action.index.IndexRequest;
import org.opensearch.core.xcontent.MediaTypeRegistry;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;

/** Class to manage the Command Manager index and index template. */
public final class IndexStateManagement extends Index {
    private static final Logger log = LogManager.getLogger(IndexStateManagement.class);

    // ISM policies names (filename without extension)
    static final String ALERTS_ROLLOVER_POLICY = "wazuh-alerts-rollover-policy";

    private final List<String> policies;

    public IndexStateManagement(String index, String template) {
        super(index, template);
        this.policies = new ArrayList<>();

        // add ISM policies to be created
        this.policies.add(ALERTS_ROLLOVER_POLICY);
    }

    private void createPolicies() {
        this.policies.forEach(this::indexPolicy);
    }

    private void indexPolicy(String policy) {
        try {
            Map<String, Object> policyFile;
            policyFile = this.indexUtils.fromFile(ALERTS_ROLLOVER_POLICY + ".json");

            IndexRequest indexRequest =
                    new IndexRequest(this.index)
                            .id(ALERTS_ROLLOVER_POLICY)
                            .source(policyFile, MediaTypeRegistry.JSON);

            client.index(indexRequest).actionGet(SetupPlugin.TIMEOUT);
            log.info("ISM policy [{}] created", policy);
        } catch (IOException e) {
            log.error("Failed to load the Wazuh rollover policy from file: {}", e.getMessage());
        } catch (ResourceAlreadyExistsException e) {
            log.error("Policy already exists, skipping creation: {}", e.getMessage());
        }
    }

    /** Overrides the parent method to also create the ISM policies after the index creation. */
    @Override
    public void initialize() {
        super.initialize();
        this.createPolicies();
    }
}
