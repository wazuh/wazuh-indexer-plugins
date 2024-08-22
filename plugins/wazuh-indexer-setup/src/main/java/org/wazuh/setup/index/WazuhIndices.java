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
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.io.InputStream;
import java.text.MessageFormat;
import java.util.*;

public class WazuhIndices {

  private static final Logger log = LogManager.getLogger(WazuhIndices.class);

  private final Client client;
  private final ClusterService clusterService;
  private final ThreadPool threadPool;

  public static final String INDEX_NAME = "wazuh-indexer-setup-plugin";
  public final Map<String, String> indexTemplateNamesMap = new HashMap<>();

  /**
   * Constructor
   * @param client Client
   * @param clusterService ClusterService
   */
  public WazuhIndices(Client client, ClusterService clusterService, ThreadPool threadPool) {
    this.client = client;
    this.clusterService = clusterService;
    this.threadPool = threadPool;
    this.indexTemplateNamesMap.put(WazuhIndices.INDEX_NAME, String.format("%s-template", WazuhIndices.INDEX_NAME));
  }

  public Map<String, String> getIndexTemplateNamesMap() {
    return this.indexTemplateNamesMap;
  }

  /**
   * Retrieves mappings from yaml files
   * @return string
   */
  public Map<String,Object> getIndexMappings(Map<String, Object> template) throws IOException {
    try {
      return (Map<String, Object>) template.get("mappings");
    } catch (Exception e) {
      throw new IOException("Could not retrieve mappings out of template file");
    }
  }

  /**
   * Retrieves index settings from yaml files
   * @return string
   */
  public Map<String,Object> getIndexSettings(Map<String, Object> template) throws IOException {
    try {
      return (Map<String, Object>) template.get("settings");
    } catch (Exception e) {
      throw new IOException("Could not settings mappings out of template file");
    }
  }

  /**
   * Get the templates from accordingly named files
   * @param indexTemplateFileName: the filename to get the json-formatted template from
   * @return a string with the json contents
   */
  public Map<String,Object> getIndexTemplateFromFile(String indexTemplateFileName) throws IOException {
    try (InputStream is = getClass().getClassLoader().getResourceAsStream(indexTemplateFileName)) {
      return toMap(is);
    } catch (IOException e) {
      String errorMessage = new MessageFormat(
          "failed to load index template file [{0}]",
          Locale.ROOT
      ).format(indexTemplateFileName);
      throw new IOException(errorMessage);
    }
  }

  /**
   * Convert from a JSON string into a <String, Object> map
   * @param template: the json formatted string
   * @return a map with the json string contents.
   */
  public Map<String, Object> toMap(String template) throws RuntimeException {
    try (XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION,template)) {
      parser.nextToken();
      return parser.map();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   * Convert from a JSON InputStream into a <String, Object> map
   * @param template: the json formatted InputStream
   * @return a map with the json string contents.
   */
  public Map<String, Object> toMap(InputStream template) throws RuntimeException {
    try (XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION, template)) {
      parser.nextToken();
      return parser.map();
    } catch (IOException e) {
      throw new RuntimeException(e);
    }
  }

  /**
   *  Loads a template
   * @param indexName: The index name to load the template for
   */
  public void putTemplate(String indexName) throws Exception {
    String indexTemplateName = getIndexTemplateNamesMap().get(indexName);
    String indexTemplateFileName = indexTemplateName + ".json";
    Map<String, Object> template = getIndexTemplateFromFile(indexTemplateFileName);
    PutIndexTemplateRequest putRequest;
    try {
      putRequest = new PutIndexTemplateRequest(indexTemplateName)
          .mapping(getIndexMappings(template))
          .settings(getIndexSettings(template))
          .name(indexTemplateName)
          .patterns(List.of(indexName + "-*"));
    } catch (Exception e) {
      throw new Exception(e.toString());
    }
    try {
      this.client.admin().indices().putTemplate(putRequest, new ActionListener<>() {

        @Override
        public void onResponse(AcknowledgedResponse acknowledgedResponse) {
          log.info("template created");
        }

        @Override
        public void onFailure(Exception e) {
          log.error("template creation failed");
        }
      });
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
    boolean indexExists = false;
    try {
      ClusterState clusterState = this.clusterService.state();
      indexExists = clusterState.getRoutingTable().hasIndex(indexName);
    } catch ( Exception e) {
      log.error(e.toString());
    }
    return indexExists;
  }
}
