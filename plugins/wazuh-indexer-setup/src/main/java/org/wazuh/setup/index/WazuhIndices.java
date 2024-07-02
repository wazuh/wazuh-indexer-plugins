/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.Locale;

public class WazuhIndices {

    private static final Logger log = LogManager.getLogger(WazuhIndices.class);

    private Client client;
    private ClusterService clusterService;

    public static String INDEX_NAME = "wazuh-indexer-setup-plugin";
    private static String INDEX_MAPPING_FILE_NAME = "index-mapping.yml";
    private static String INDEX_SETTING_FILE_NAME = "index-settings.yml";

    /**
     * Constructor
     * @param client Client
     * @param clusterService ClusterService
     */
    public WazuhIndices(Client client, ClusterService clusterService) {
        this.client = client;
        this.clusterService = clusterService;
    }

    /**
     *
     * @return string
     */
    public String getIndexMapping() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(INDEX_MAPPING_FILE_NAME)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(is, out);
            return out.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            String errorMessage = new MessageFormat(
                "failed to load index mapping file [{0}]",
                Locale.ROOT
            ).format(INDEX_MAPPING_FILE_NAME);
            log.error(errorMessage, e);
            throw new IllegalStateException(errorMessage, e);
        }
    }

    /**
     *
     * @return string
     */
    public String getIndexSettings() {
        try (InputStream is = getClass().getClassLoader().getResourceAsStream(INDEX_SETTING_FILE_NAME)) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            Streams.copy(is, out);
            return out.toString(StandardCharsets.UTF_8);
        } catch (Exception e) {
            String errorMessage = new MessageFormat(
                "failed to load index settings file [{0}]",
                Locale.ROOT
            ).format(INDEX_SETTING_FILE_NAME);
            log.error(errorMessage, e);
            throw new IllegalStateException(errorMessage, e);
        }
    }


    /**
     * Create Wazuh's Indices.
     */
    public void create(ActionListener<CreateIndexResponse> actionListener) throws IOException {


        if (!indexExists(WazuhIndices.INDEX_NAME)) {
            CreateIndexRequest indexRequest = new CreateIndexRequest(WazuhIndices.INDEX_NAME)
                    .mapping(getIndexMapping(), XContentType.YAML)
                    .settings(getIndexSettings(), XContentType.YAML);
            client.admin().indices().create(indexRequest, actionListener);
        }
    }


    /**
     * Generic indexExists method
     */
    public boolean indexExists(String indexName) {
        ClusterState clusterState = clusterService.state();
        return clusterState.getRoutingTable().hasIndex(WazuhIndices.INDEX_NAME);
    }
}
