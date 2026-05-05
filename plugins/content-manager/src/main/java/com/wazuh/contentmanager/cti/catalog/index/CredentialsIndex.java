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
package com.wazuh.contentmanager.cti.catalog.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.ResourceAlreadyExistsException;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;

/** Manages the hidden .wazuh-cti-credentials index used to persist the CTI access token. */
public class CredentialsIndex {
    private static final Logger log = LogManager.getLogger(CredentialsIndex.class);

    public static final String INDEX_NAME = ".wazuh-cti-credentials";
    private static final String MAPPING_PATH = "/mappings/credentials-mapping.json";
    private static final String DOCUMENT_ID = "credentials";
    static final String ACCESS_TOKEN_FIELD = "access_token";

    private final Client client;
    private final PluginSettings pluginSettings;

    /**
     * Constructor.
     *
     * @param client OpenSearch client used for index operations.
     */
    public CredentialsIndex(Client client) {
        this.client = client;
        this.pluginSettings = PluginSettings.getInstance();
    }

    /**
     * Stores the access token in the credentials index. Overwrites any previously stored value.
     *
     * @param accessToken the CTI access token to persist.
     * @return the IndexResponse from the operation.
     * @throws ExecutionException if the client failed to execute the request.
     * @throws InterruptedException if the current thread was interrupted.
     * @throws TimeoutException if the operation exceeded the configured timeout.
     * @throws IOException if serialization fails.
     */
    public IndexResponse storeCredentials(String accessToken)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        if (!ClusterInfo.indexStatusCheck(
                this.client, INDEX_NAME, this.pluginSettings.getClientTimeout())) {
            throw new RuntimeException("Index not ready: " + INDEX_NAME);
        }
        IndexRequest request =
                new IndexRequest()
                        .index(INDEX_NAME)
                        .id(DOCUMENT_ID)
                        .source(
                                XContentFactory.jsonBuilder()
                                        .startObject()
                                        .field(ACCESS_TOKEN_FIELD, accessToken)
                                        .endObject());
        return this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
    }

    /**
     * Retrieves the stored access token from the index.
     *
     * @return the access token string, or null if not found.
     * @throws ExecutionException if the client failed to execute the request.
     * @throws InterruptedException if the current thread was interrupted.
     * @throws TimeoutException if the operation exceeded the configured timeout.
     */
    public String getAccessToken()
            throws ExecutionException, InterruptedException, TimeoutException {
        if (!ClusterInfo.indexStatusCheck(
                this.client, INDEX_NAME, this.pluginSettings.getClientTimeout())) {
            throw new RuntimeException("Index not ready: " + INDEX_NAME);
        }
        GetRequest request = new GetRequest().index(INDEX_NAME).id(DOCUMENT_ID).preference("_local");
        GetResponse response =
                this.client.get(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        if (!response.isExists()) {
            return null;
        }
        Map<String, Object> source = response.getSourceAsMap();
        return source != null ? (String) source.get(ACCESS_TOKEN_FIELD) : null;
    }

    /**
     * Checks whether the credentials index exists.
     *
     * @return true if the index exists, false otherwise.
     */
    public boolean exists() {
        return ClusterInfo.indexExists(this.client, INDEX_NAME);
    }

    /**
     * Creates the credentials index with hidden settings and credentials mapping.
     *
     * @return the CreateIndexResponse, or null if the index already exists.
     * @throws ExecutionException if the client failed to execute the request.
     * @throws InterruptedException if the current thread was interrupted.
     * @throws TimeoutException if the operation exceeded the configured timeout.
     */
    public CreateIndexResponse createIndex()
            throws ExecutionException, InterruptedException, TimeoutException {
        Settings settings =
                Settings.builder().put("index.number_of_replicas", 0).put("hidden", true).build();

        String mappings;
        try {
            mappings = this.loadMappingFromResources();
        } catch (IOException e) {
            log.error("Could not read mappings for index [{}]", INDEX_NAME);
            return null;
        }

        CreateIndexRequest request =
                new CreateIndexRequest().index(INDEX_NAME).mapping(mappings).settings(settings);

        try {
            return this.client
                    .admin()
                    .indices()
                    .create(request)
                    .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        } catch (ExecutionException | TimeoutException e) {
            boolean alreadyExists =
                    e instanceof ExecutionException
                            ? ExceptionsHelper.unwrap(e, ResourceAlreadyExistsException.class) != null
                            : this.exists();
            if (alreadyExists) {
                log.debug("Index [{}] already exists, skipping creation.", INDEX_NAME);
                return null;
            }
            throw e;
        }
    }

    /**
     * Loads the index mapping JSON from the resources folder.
     *
     * @return the mapping as a JSON string.
     * @throws IOException if reading the resource fails.
     */
    protected String loadMappingFromResources() throws IOException {
        try (InputStream is = this.getClass().getResourceAsStream(MAPPING_PATH)) {
            if (is == null) {
                throw new java.io.FileNotFoundException("Mapping file not found: " + MAPPING_PATH);
            }
            return new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
    }
}
