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

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.core.xcontent.MediaTypeRegistry;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.model.IndexTemplate;
import com.wazuh.setup.settings.PluginSettings;

/**
 * Initializes the Index State Management internal index <code>.opendistro-ism-config</code>.
 * Creates ISM policies. Extends {@link Index}.
 */
public class IndexStateManagement extends Index {
    private static final Logger log = LogManager.getLogger(IndexStateManagement.class);

    // ISM index name
    public static final String ISM_INDEX_NAME = ".opendistro-ism-config";

    // ISM policies names (filename without extension)
    static final String STREAM_ROLLOVER_POLICY = "stream-rollover-policy";
    static final String STREAM_ROLLOVER_POLICY_PATH = "policies/" + STREAM_ROLLOVER_POLICY + ".json";

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
        this.policies.add(STREAM_ROLLOVER_POLICY);
    }

    /**
     * Creates every ISM policy added to {@link #policies} by passing it to {@link
     * #indexPolicy(String)}.
     */
    private void createPolicies() {
        this.policies.forEach(this::indexPolicy);
    }

    /**
     * Indexes the given ISM policy to the ISM internal index.
     *
     * @param policy policy name to create.
     */
    private void indexPolicy(String policy) {
        try {
            Map<String, Object> policyFile;
            policyFile = this.jsonUtils.fromFile(STREAM_ROLLOVER_POLICY_PATH);

            IndexRequest indexRequest =
                    new IndexRequest(this.index)
                            .id(STREAM_ROLLOVER_POLICY)
                            .source(policyFile, MediaTypeRegistry.JSON);

            this.client
                    .index(indexRequest)
                    .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
            log.info("ISM policy [{}] created", policy);
        } catch (IOException e) {
            log.error("Failed to load the ISM policy from file: {}", e.getMessage());
        } catch (ResourceAlreadyExistsException e) {
            log.error("Policy already exists, skipping creation: {}", e.getMessage());
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index also failed. Original exception is rethrown.
            if (!this.retry_index_creation) {
                log.error("Initialization of policy [{}] finally failed. The node will shut down.", policy);
                throw e;
            }
            log.warn("Operation to create the policy [{}] timed out. Retrying...", policy);
            this.retry_index_creation = false;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.indexPolicy(policy);
        }
    }

    /**
     * Creates an index.
     *
     * @param index Name of the index to create.
     */
    @Override
    public void createIndex(String index) {
        try {
            if (!this.indexExists(index)) {
                // For some reason the index template is not applied to the ISM internal index
                // ".opendistro-ism-config", so we explicitly set the index mappings and settings
                // as part of the CreateIndexRequest.
                // Read JSON index template
                ObjectMapper mapper = new ObjectMapper();
                InputStream is =
                        StreamIndex.class.getClassLoader().getResourceAsStream(this.template + ".json");
                IndexTemplate indexTemplate = mapper.readValue(is, IndexTemplate.class);

                CreateIndexRequest request =
                        new CreateIndexRequest(index)
                                .mapping(indexTemplate.getMappings())
                                .settings(indexTemplate.getSettings());
                CreateIndexResponse createIndexResponse =
                        this.client
                                .admin()
                                .indices()
                                .create(request)
                                .actionGet(PluginSettings.getTimeout(this.clusterService.getSettings()));
                log.info(
                        "Index created successfully: {} {}",
                        createIndexResponse.index(),
                        createIndexResponse.isAcknowledged());
            }
        } catch (ResourceAlreadyExistsException e) {
            log.info("Index {} already exists. Skipping.", index);
        } catch (IOException e) {
            log.error(
                    "Error reading index template from filesystem [{}]. Caused by: {}",
                    this.template,
                    e.toString());
        } catch (
                Exception
                        e) { // TimeoutException may be raised by actionGet(), but we cannot catch that one.
            // Exit condition. Re-attempt to create the index also failed. Original exception is rethrown.
            if (!this.retry_index_creation) {
                log.error("Initialization of index [{}] finally failed. The node will shut down.", index);
                throw e;
            }
            log.warn("Operation to create the index [{}] timed out. Retrying...", index);
            this.retry_index_creation = false;
            this.sleep(PluginSettings.getBackoff(this.clusterService.getSettings()));
            this.createIndex(index);
        }
    }

    /** Overrides the parent method to also create the ISM policies after the index creation. */
    @Override
    public void initialize() {
        this.createIndex(this.index);
        this.retry_index_creation = true; // Re-used variable to retry initialization of ISM policies.
        this.createPolicies();
    }
}
