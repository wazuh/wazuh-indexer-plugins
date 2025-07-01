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
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.core.xcontent.MediaTypeRegistry;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.SetupPlugin;

/**
 * Initializes the Index State Management internal index <code>.opendistro-ism-config</code>.
 * Creates ISM policies. Extends {@link Index}.
 */
public class IndexStateManagement extends Index {
    private static final Logger log = LogManager.getLogger(IndexStateManagement.class);

    // ISM policies names (filename without extension)
    static final String ALERTS_ROLLOVER_POLICY = "wazuh-alerts-rollover-policy";

    private final List<String> policies;

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    public IndexStateManagement(String index, String template) {
        super(index, template);
        this.policies = new ArrayList<>();

        // Add ISM policies to be created
        this.policies.add(ALERTS_ROLLOVER_POLICY);
    }

    /**
     * Creates every ISM policy added to {@link #policies} by passing it to {@link
     * #indexPolicy(String)}.
     */
    private boolean createPolicies() {
        for (String policy : this.policies) {
            if (!indexPolicy(policy)) {
                return false;
            }
        }
        return true;
    }

    /**
     * Indexes the given ISM policy to the ISM internal index.
     *
     * @param policy policy name to create.
     * @return true if the policy was correctly indexed or already existed, and false otherwise.
     */
    private boolean indexPolicy(String policy) {
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
            log.error("Failed to load the ISM policy from file: {}", e.getMessage());
            return false;
        } catch (ResourceAlreadyExistsException e) {
            log.error("Policy already exists, skipping creation: {}", e.getMessage());
        }
        return true;
    }

    /**
     * Creates an index.
     *
     * @param index Name of the index to create.
     * @return true if the index was correctly created or already existed, and false otherwise.
     */
    @Override
    public boolean createIndex(String index) {
        try {
            if (!this.indexExists(index)) {
                // For some reason the index template is not applied to the ISM internal index
                // ".opendistro-ism-config", so we explicitly set the index mappings and settings
                // as part of the CreateIndexRequest.
                Map<String, Object> templateFile = this.indexUtils.fromFile(this.template + ".json");

                CreateIndexRequest request =
                        new CreateIndexRequest(index)
                                .mapping(this.indexUtils.get(templateFile, "mappings"))
                                .settings(this.indexUtils.get(templateFile, "settings"));
                CreateIndexResponse createIndexResponse =
                        this.client.admin().indices().create(request).actionGet(SetupPlugin.TIMEOUT);
                log.info(
                        "Index created successfully: {} {}",
                        createIndexResponse.index(),
                        createIndexResponse.isAcknowledged());
            }

        } catch (IOException e) {
            log.error("Error reading index template from filesystem {}", this.template);
            return false;
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index {} already exists. Skipping.", index);
        }
        return true;
    }

    /**
     * Overrides the parent method to also create the ISM policies after the index creation.
     * @return true if the index and the policies are correctly created, and false otherwise.
     */
    @Override
    public boolean initialize() {
        boolean indexCreated = this.createIndex(this.index);
        boolean policiesCreated = this.createPolicies();

        return indexCreated && policiesCreated;
    }
}
