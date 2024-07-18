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
import java.text.MessageFormat;
import java.util.Locale;

import org.junit.Before;
import org.opensearch.client.Client;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.util.io.Streams;
import org.opensearch.test.OpenSearchTestCase;

public class WazuhIndexerSetupTests extends OpenSearchTestCase {

private WazuhIndices wazuhIndices;
private Client client;
private ClusterService clusterService;
public static final String INDEX_NAME = "wazuh-indexer-setup-plugin";
private static final String INDEX_MAPPING_FILE_NAME = "index-mapping.yml";
private static final String INDEX_SETTING_FILE_NAME = "index-settings.yml";

  @Before
  public void setUp() throws Exception {
    super.setUp();
    this.wazuhIndices = new WazuhIndices(client, clusterService);
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
    assertEquals(0,0);

  }

  public void testCreate() {
    assertEquals(0,0);

  }

  public void testIndexExists() {
    assertEquals(0,0);

  }

}
