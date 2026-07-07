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
import org.opensearch.action.delete.DeleteRequest;
import org.opensearch.action.delete.DeleteResponse;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.WriteRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.ClusterInfo;
import com.wazuh.contentmanager.utils.Constants;

/** Manages the hidden .wazuh-internal-state index used to persist the CTI access token. */
public class CredentialsIndex {
    private static final Logger log = LogManager.getLogger(CredentialsIndex.class);

    public static final String INDEX_NAME = ".wazuh-internal-state";
    private static final String MAPPING_PATH = "/mappings/credentials-mapping.json";
    private static final String DOCUMENT_ID = "credentials";
    static final String ACCESS_TOKEN_FIELD = "access_token";

    private final Client client;
    private final ThreadPool threadPool;
    private final PluginSettings pluginSettings;

    /**
     * Constructor.
     *
     * @param client OpenSearch client used for index operations.
     * @param threadPool Thread pool used to stash security context for system index access.
     */
    public CredentialsIndex(Client client, ThreadPool threadPool) {
        this.client = client;
        this.threadPool = threadPool;
        this.pluginSettings = PluginSettings.getInstance();
    }

    /**
     * Stashes the current thread context (removing the caller's security identity) so that subsequent
     * client operations run as the plugin itself, which has system index access.
     *
     * @return a {@link ThreadContext.StoredContext} that must be closed to restore the original
     *     context (use in try-with-resources).
     */
    private ThreadContext.StoredContext stashContext() {
        return this.threadPool.getThreadContext().stashContext();
    }

    /**
     * Stores the access token in the credentials index, base64-encoded at rest. Overwrites any
     * previously stored value.
     *
     * @param accessToken the CTI access token to persist (plaintext).
     * @throws ExecutionException if the client failed to execute the request.
     * @throws InterruptedException if the current thread was interrupted.
     * @throws TimeoutException if the operation exceeded the configured timeout.
     * @throws IOException if serialization fails.
     */
    public void storeCredentials(String accessToken)
            throws ExecutionException, InterruptedException, TimeoutException, IOException {
        // Stash the caller's security context so the client runs as the plugin, which has system index
        // access.
        try (ThreadContext.StoredContext ignoredContext = this.stashContext()) {
            if (!this.exists()) {
                log.info("Index [{}] not found. Recreating before storing credentials.", INDEX_NAME);
                this.createIndex();
            }
            if (!ClusterInfo.indexStatusCheck(
                    this.client, INDEX_NAME, this.pluginSettings.getClientTimeout())) {
                throw new RuntimeException("Index not ready: " + INDEX_NAME);
            }
            String encoded =
                    Base64.getEncoder().encodeToString(accessToken.getBytes(StandardCharsets.UTF_8));
            IndexRequest request =
                    new IndexRequest()
                            .index(INDEX_NAME)
                            .id(DOCUMENT_ID)
                            .source(
                                    XContentFactory.jsonBuilder()
                                            .startObject()
                                            .field(ACCESS_TOKEN_FIELD, encoded)
                                            .endObject())
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            this.client.index(request).get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        }
    }

    /**
     * Retrieves the stored access token from the index, decoded from its base64 form.
     *
     * @return the plaintext access token, or null if not found.
     * @throws ExecutionException if the client failed to execute the request.
     * @throws InterruptedException if the current thread was interrupted.
     * @throws TimeoutException if the operation exceeded the configured timeout.
     */
    public String getAccessToken() throws ExecutionException, InterruptedException, TimeoutException {
        // Stash the caller's security context so the client runs as the plugin, which has system index
        // access.
        try (ThreadContext.StoredContext ignoredContext = this.stashContext()) {
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
            if (source == null) {
                return null;
            }
            String stored = (String) source.get(ACCESS_TOKEN_FIELD);
            return stored != null
                    ? new String(Base64.getDecoder().decode(stored), StandardCharsets.UTF_8)
                    : null;
        }
    }

    /**
     * Deletes the credentials document from the index, preserving the index itself.
     *
     * @return the DeleteResponse from the operation.
     * @throws ExecutionException if the client failed to execute the request.
     * @throws InterruptedException if the current thread was interrupted.
     * @throws TimeoutException if the operation exceeded the configured timeout.
     */
    public DeleteResponse deleteDocument()
            throws ExecutionException, InterruptedException, TimeoutException {
        // Stash the caller's security context so the client runs as the plugin, which has system index
        // access.
        try (ThreadContext.StoredContext ignoredContext = this.stashContext()) {
            if (!this.exists()) {
                log.debug("Index [{}] does not exist, nothing to delete.", INDEX_NAME);
                return null;
            }
            DeleteRequest request =
                    new DeleteRequest(INDEX_NAME, DOCUMENT_ID)
                            .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE);
            return this.client
                    .delete(request)
                    .get(this.pluginSettings.getClientTimeout(), TimeUnit.SECONDS);
        }
    }

    /**
     * Checks whether the credentials index exists.
     *
     * @return true if the index exists, false otherwise.
     */
    public boolean exists() {
        // Stash the caller's security context so the client runs as the plugin, which has system index
        // access.
        try (ThreadContext.StoredContext ignoredContext = this.stashContext()) {
            return ClusterInfo.indexExists(this.client, INDEX_NAME);
        }
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
        // Stash the caller's security context so the client runs as the plugin, which has system index
        // access.
        try (ThreadContext.StoredContext ignoredContext = this.stashContext()) {
            Settings settings =
                    Settings.builder()
                            .put("index.number_of_replicas", 0)
                            .put("index.hidden", true)
                            .put(Constants.KEY_INDEX_CODEC, Constants.CODEC_ZSTD)
                            .put(Constants.KEY_INDEX_REFRESH_INTERVAL, Constants.REFRESH_INTERVAL_DISABLED)
                            .build();

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
