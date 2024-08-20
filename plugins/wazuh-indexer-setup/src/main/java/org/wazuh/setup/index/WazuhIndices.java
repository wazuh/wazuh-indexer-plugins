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
import org.apache.logging.log4j.message.ParameterizedMessage;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.bulk.BackoffPolicy;
import org.opensearch.action.index.IndexRequestBuilder;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.io.Streams;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.concurrency.OpenSearchRejectedExecutionException;
import org.opensearch.threadpool.ThreadPool;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.List;
import java.util.Iterator;
import java.util.Locale;

import static org.opensearch.common.unit.TimeValue.timeValueMillis;

public class WazuhIndices {

  private static final Logger log = LogManager.getLogger(WazuhIndices.class);

  private final Client client;
  private final ClusterService clusterService;
  private final ThreadPool threadPool;

  public static final String INDEX_NAME = "wazuh-indexer-setup-plugin";
  private static final String INDEX_MAPPING_FILE_NAME = "index-mapping.yml";
  private static final String INDEX_SETTING_FILE_NAME = "index-settings.yml";
  public static final List<String> INDEX_NAMES = List.of(WazuhIndices.INDEX_NAME);

  /**
   * Constructor
   * @param client Client
   * @param clusterService ClusterService
   */
  public WazuhIndices(Client client, ClusterService clusterService, ThreadPool threadPool) {
    this.client = client;
    this.clusterService = clusterService;
    this.threadPool = threadPool;
  }

  /**
   * Retrieves mappings from yaml files
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
   * Retrieves index settings from yaml files
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
   *  Loads a template
   * @param actionListener: The ActionListener that will handle the response.
   */
  public void putTemplate(ActionListener<AcknowledgedResponse> actionListener) throws IOException {
    String indexTemplate = "wazuh";
    PutIndexTemplateRequest putRequest = new PutIndexTemplateRequest()
        .name(indexTemplate)
        .patterns(List.of("wazuh-*"));
    try {
      this.client.admin().indices().putTemplate(putRequest, actionListener);

    } catch (Exception e) {
      //String errorMessage = new MessageFormat(
      //        "failed to create index template [{0}]",
      //        Locale.ROOT
      //).format(indexTemplate);
      //log.error(errorMessage, e);
      //throw new IllegalStateException(errorMessage, e);
      log.error("Failed to create index template {0}");
      throw new IllegalStateException(e);
    }
  }

  /**
   * Create Wazuh's Indices.
   * @param indexName: Name of the index to be created
   */
  public void create(String indexName) {
    try {
      if (!indexExists(WazuhIndices.INDEX_NAME)) {
        CreateIndexRequest request = new CreateIndexRequest(indexName);
        CreateIndexResponse createIndexResponse = client.admin().indices().create(request).actionGet();
        log.info("Index created successfully: {}", createIndexResponse);
      }
    } catch (Exception e) {
      log.error("Error while creating index: {}", e.getMessage());
    }
  }

  /**
   * Generic indexExists method
   * @param indexName: The index name to be checked for
   */
  public boolean indexExists(String indexName) {
    ClusterState clusterState = this.clusterService.state();
    return clusterState.getRoutingTable().hasIndex(indexName);
  }
}
