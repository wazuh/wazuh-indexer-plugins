/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.wazuh.setup.index;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import org.junit.After;
import org.junit.Before;
import org.opensearch.action.admin.indices.create.CreateIndexRequest;
import org.opensearch.action.admin.indices.create.CreateIndexResponse;
import org.opensearch.action.admin.indices.template.put.PutIndexTemplateRequest;
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
import org.opensearch.cluster.ClusterState;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.io.Streams;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.TestThreadPool;
import org.opensearch.threadpool.ThreadPool;

import static org.mockito.Mockito.*;
import static org.opensearch.test.ClusterServiceUtils.createClusterService;

public class WazuhIndexerSetupTests extends OpenSearchTestCase {

  private WazuhIndices wazuhIndices;
  private ThreadPool threadPool;
  public ClusterService clusterService;
  private static final String INDEX_MAPPING_FILE_NAME = "index-mapping.yml";
  private static final String INDEX_SETTING_FILE_NAME = "index-settings.yml";
  private Client mockClient;

  /**
   * Creates the necessary mocks and spies
   * @throws Exception
   */
  @Before
  public void setUp() throws Exception {
    super.setUp();

    this.threadPool = new TestThreadPool("WazuhIndexerSetupPluginServiceTests");
    this.clusterService = spy(createClusterService(threadPool));
    this.mockClient = mock(Client.class);
    this.wazuhIndices = new WazuhIndices(mockClient, clusterService, threadPool);
  }

  /**
   * Shuts the test cluster down properly after tests are done
   * @throws Exception
   */
  @After
  public void testTearDown() throws Exception {
    this.threadPool.shutdownNow();
    this.clusterService.close();
  }

  /**
   * Tests if the index mappings returned by the getIndexMapping() function
   * match the contents of the yaml file
   * @throws IOException
   */
  public void testGetIndexMapping() throws IOException {
    String indexMapping = this.wazuhIndices.getIndexMapping();
    InputStream is = WazuhIndices.class.getClassLoader().getResourceAsStream(INDEX_MAPPING_FILE_NAME);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Streams.copy(is, out);
    assertEquals(out.toString(StandardCharsets.UTF_8),this.wazuhIndices.getIndexMapping());
  }

  public void testGetIndexSettings() throws IOException {
    InputStream is = getClass().getClassLoader().getResourceAsStream(INDEX_SETTING_FILE_NAME);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Streams.copy(is, out);
    assertEquals(out.toString(StandardCharsets.UTF_8), this.wazuhIndices.getIndexSettings());
  }

  /**
   * Tests the putTemplate method
   */

  public void testPutTemplate() {

    AdminClient mockAdminClient = mock(AdminClient.class);
    IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
    when(this.mockClient.admin()).thenReturn(mockAdminClient);
    when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);

    doAnswer( invocation -> {
      ActionListener<AcknowledgedResponse> listener = invocation.getArgument(1);
      listener.onResponse(new AcknowledgedResponse(true));
      return null;
    }).when(mockIndicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class), any(ActionListener.class));

    ActionListener<AcknowledgedResponse> actionListener = new ActionListener<AcknowledgedResponse>() {
      @Override
      public void onResponse(AcknowledgedResponse acknowledgedResponse) {
        assertTrue(acknowledgedResponse.isAcknowledged());
      }
      @Override
      public void onFailure(Exception e) {
        logger.error("Mock error putting template: {}", e.toString());
      }
    };

    this.wazuhIndices.putTemplate(actionListener);

    doAnswer( invocation -> {
      ActionListener<AcknowledgedResponse> listener = invocation.getArgument(1);
      listener.onFailure(new Exception("Mock exception on putTemplate"));
      return null;
    }).when(mockIndicesAdminClient).putTemplate(any(PutIndexTemplateRequest.class), any(ActionListener.class));

    this.wazuhIndices.putTemplate(actionListener);
  }

  /**
   * Tests creating an index
   */
  public void testCreate() {
    AdminClient mockAdminClient = mock(AdminClient.class);
    IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
    when(this.mockClient.admin()).thenReturn(mockAdminClient);
    when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);

    doAnswer( invocation -> {
      ActionListener<CreateIndexResponse> listener = invocation.getArgument(1);
      listener.onResponse(new CreateIndexResponse(true,true, WazuhIndices.INDEX_NAME));
      return null;
    }).when(mockIndicesAdminClient).create(any(CreateIndexRequest.class), any(ActionListener.class));

    ActionListener<CreateIndexResponse> actionListener = new ActionListener<>() {
      @Override
      public void onResponse(CreateIndexResponse createIndexResponse) {
        logger.info("Mock successful index creation");
        assertTrue(createIndexResponse.isAcknowledged());
      }

      @Override
      public void onFailure(Exception e) {
        logger.error("Mock error creating index: {}", e.toString());
      }
    };

    try {
      this.wazuhIndices.create(WazuhIndices.INDEX_NAME);
    }
    catch (Exception e) {
      logger.error(e);
    }

    doAnswer( invocation -> {
      ActionListener<CreateIndexResponse> listener = invocation.getArgument(1);
      listener.onFailure(new Exception("Mock Exception"));
      return null;
    }).when(mockIndicesAdminClient).create(any(CreateIndexRequest.class), any(ActionListener.class));

    try {
      this.wazuhIndices.create(WazuhIndices.INDEX_NAME);
    }
    catch (Exception e) {
      logger.error(e);
    }
  }

  /**
   * Tests the indexExists() method
   */
  public void testIndexExists() {
    ClusterState mockClusterState = mock(ClusterState.class);
    RoutingTable mockRoutingTable = mock(RoutingTable.class);
    when(this.clusterService.state()).thenReturn(mockClusterState);
    when(mockClusterState.getRoutingTable()).thenReturn(mockRoutingTable);
    /* Test with existent index response */
    when(mockRoutingTable.hasIndex(anyString())).thenReturn(true);
    logger.error(this.wazuhIndices.indexExists(WazuhIndices.INDEX_NAME));
    /* Test with non-existent index response */
    when(mockRoutingTable.hasIndex(anyString())).thenReturn(false);
    logger.error(this.wazuhIndices.indexExists(WazuhIndices.INDEX_NAME));
  }
}
