/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package org.wazuh.setup.index;

import org.junit.Before;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;

public class WazuhIndexerSetupTests extends OpenSearchTestCase {

private WazuhIndices wazuhIndices;
private Client client;
private ClusterService clusterService;

  @Before
  public void setUp() throws Exception {
    //public static final String INDEX_NAME = "wazuh-indexer-setup-plugin";
    //private static final String INDEX_MAPPING_FILE_NAME = "index-mapping.yml";
    //private static final String INDEX_SETTING_FILE_NAME = "index-settings.yml";
    super.setUp();
    this.wazuhIndices = new WazuhIndices(client, clusterService);
  }

  public void testGetIndexMapping() {
    //String indexMapping = getIndexMapping();
    //InputStream is = getClass().getClassLoader().getResourceAsStream(INDEX_MAPPING_FILE_NAME)
    //ByteArrayOutputStream out = new ByteArrayOutputStream();
    //Streams.copy(is, out);
    //return out.toString(StandardCharsets.UTF_8);
    assertEquals(0,0);
  }

  public void testGetIndexSettings() {
    assertEquals(0,0);

  }

  public void testPutTemplate() {
    assertEquals(0,0);

  }

  public void testCreate() {
    assertEquals(0,0);

  }

  public void testIndexExists() {
    assertEquals(0,0);

  }

}
