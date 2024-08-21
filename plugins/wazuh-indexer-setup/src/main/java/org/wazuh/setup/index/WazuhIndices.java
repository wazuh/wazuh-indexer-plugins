/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.wazuh.setup.index;

import com.fasterxml.jackson.core.JsonParser;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.io.Streams;
import org.opensearch.common.xcontent.json.JsonXContent;
import org.opensearch.common.xcontent.json.JsonXContentParser;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.xcontent.DeprecationHandler;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.core.xcontent.XContentParser;
import org.opensearch.threadpool.ThreadPool;
import com.fasterxml.jackson.core.JsonFactory;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.text.MessageFormat;
import java.util.*;

public class WazuhIndices {

  private static final Logger log = LogManager.getLogger(WazuhIndices.class);

  private final Client client;
  private final ClusterService clusterService;
  private final ThreadPool threadPool;

  public static final String INDEX_NAME = "wazuh-indexer-setup-plugin";
  private static final String INDEX_MAPPING_FILE_NAME = "index-mapping.yml";
  private static final String INDEX_SETTING_FILE_NAME = "index-settings.yml";
  public static final List<String> INDEX_NAMES = List.of(WazuhIndices.INDEX_NAME);
  public static final Map<String, String> templates = new HashMap<>();

  /**
   * Constructor
   * @param client Client
   * @param clusterService ClusterService
   */
  public WazuhIndices(Client client, ClusterService clusterService, ThreadPool threadPool) {
    this.client = client;
    this.clusterService = clusterService;
    this.threadPool = threadPool;
    templates.put(WazuhIndices.INDEX_NAME, String.format("%s-template", WazuhIndices.INDEX_NAME));
  }

  /**
   * Retrieves mappings from yaml files
   * @return string
   */
  public Map<String, Object> getIndexMapping(String indexName) {
    String indexTemplate = templates.get(indexName);
    String indexTemplateFileName = indexTemplate + ".json";
    return (Map<String, Object>) stringToMap(getIndexTemplateFromFile(indexTemplateFileName)).get("mappings");
  }

  /**
   * Retrieves index settings from yaml files
   * @return string
   */
  public Map<String,Object> getIndexSettings(String indexName) {
    String indexTemplate = templates.get(indexName);
    String indexTemplateFileName = indexTemplate + ".json";
    return (Map<String, Object>) stringToMap(getIndexTemplateFromFile(indexTemplateFileName)).get("settings");
  }

  /**
   * Get the templates from accordingly named files
   * @param indexTemplateFileName: the filename to get the json-formatted template from
   * @return a string with the json contents
   */
  public String getIndexTemplateFromFile(String indexTemplateFileName) {
    try (InputStream is = getClass().getClassLoader().getResourceAsStream(indexTemplateFileName)) {
      ByteArrayOutputStream out = new ByteArrayOutputStream();
      Streams.copy(is, out);
      return out.toString(StandardCharsets.UTF_8);
    } catch (Exception e) {
      String errorMessage = new MessageFormat(
          "failed to load index template file [{0}]",
          Locale.ROOT
      ).format(indexTemplateFileName);
      log.error(errorMessage, e);
      throw new IllegalStateException(errorMessage, e);
    }
  }

  /**
   * Convert from a JSON string into a <String, Object> map
   * @param template: the json formatted string
   * @return a map with the json string contents.
   */
  public Map<String, Object> stringToMap(String template) {
    try (XContentParser parser = JsonXContent.jsonXContent.createParser(NamedXContentRegistry.EMPTY, DeprecationHandler.THROW_UNSUPPORTED_OPERATION,template)) {
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
  public void putTemplate(String indexName) throws IOException {
    String indexTemplate = templates.get(indexName);
    String indexTemplateFileName = indexTemplate + ".json";
    PutIndexTemplateRequest putRequest = new PutIndexTemplateRequest(indexTemplate).mapping(getIndexMapping(indexName))
        .settings(getIndexSettings(indexName))
        .name(indexTemplate)
        .patterns(List.of(indexName + "-*"));
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
    ClusterState clusterState = this.clusterService.state();
    return clusterState.getRoutingTable().hasIndex(indexName);
  }
}
