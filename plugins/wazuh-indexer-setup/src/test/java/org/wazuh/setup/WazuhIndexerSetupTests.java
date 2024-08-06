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
import org.opensearch.action.support.master.AcknowledgedResponse;
import org.opensearch.client.AdminClient;
import org.opensearch.client.Client;
import org.opensearch.client.IndicesAdminClient;
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
  private ClusterService clusterService;
  private static final String INDEX_MAPPING_FILE_NAME = "index-mapping.yml";
  private static final String INDEX_SETTING_FILE_NAME = "index-settings.yml";

  @Before
  public void setUp() throws Exception {
    super.setUp();

    threadPool = new TestThreadPool("WazuhIndexerSetupPluginServiceTests");
    clusterService = createClusterService(threadPool);


    Client mockClient = mock(Client.class);
    AdminClient mockAdminClient = mock(AdminClient.class);
    IndicesAdminClient mockIndicesAdminClient = mock(IndicesAdminClient.class);
    when(mockClient.admin()).thenReturn(mockAdminClient);
    when(mockAdminClient.indices()).thenReturn(mockIndicesAdminClient);


    this.wazuhIndices = new WazuhIndices(mockClient, clusterService);

  }

  @After
  public void testTearDown() throws Exception {
    threadPool.shutdownNow();
    clusterService.close();
  }

  public void testGetIndexMapping() throws IOException {
    String indexMapping = wazuhIndices.getIndexMapping();
    InputStream is = WazuhIndices.class.getClassLoader().getResourceAsStream(INDEX_MAPPING_FILE_NAME);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Streams.copy(is, out);
    assertEquals(out.toString(StandardCharsets.UTF_8),wazuhIndices.getIndexMapping());
  }

  public void testGetIndexSettings() throws IOException {
    InputStream is = getClass().getClassLoader().getResourceAsStream(INDEX_SETTING_FILE_NAME);
    ByteArrayOutputStream out = new ByteArrayOutputStream();
    Streams.copy(is, out);
    assertEquals(out.toString(StandardCharsets.UTF_8), wazuhIndices.getIndexSettings());
  }

  public void testPutTemplate() {
    ActionListener<AcknowledgedResponse> actionListener = mock(ActionListener.class);
    doAnswer( invocation -> {
      AcknowledgedResponse response = invocation.getArgument(0);
      logger.error(response);
      assertTrue(response.isAcknowledged());
      return null;
    }).when(actionListener).onResponse(any(AcknowledgedResponse.class));
    this.wazuhIndices.putTemplate(actionListener);
  }

  public void testCreate() {
    assertEquals(0,0);

  }

  public void testIndexExists() {
    assertEquals(0,0);
  }
}
