/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.synchronizer;

import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/** Tests for the DecodersConsumerSynchronizer class. */
public class DecodersConsumerSynchronizerTests extends OpenSearchTestCase {

    private DecodersConsumerSynchronizer synchronizer;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        this.synchronizer = new DecodersConsumerSynchronizer(client, consumersIndex, environment);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    public void testGetContextReturnsExpectedValue() {
        String context = synchronizer.getContext();

        Assert.assertEquals("decoders_development_0.0.1", context);
    }

    public void testGetConsumerReturnsExpectedValue() {
        String consumer = synchronizer.getConsumer();

        Assert.assertEquals("decoders_development_0.0.1", consumer);
    }

    public void testGetMappingsReturnsExpectedMappings() {
        Map<String, String> mappings = synchronizer.getMappings();

        Assert.assertNotNull(mappings);
        Assert.assertEquals(4, mappings.size());
        Assert.assertEquals("/mappings/cti-decoders-mappings.json", mappings.get("decoder"));
        Assert.assertEquals("/mappings/cti-kvdbs-mappings.json", mappings.get("kvdb"));
        Assert.assertEquals(
                "/mappings/cti-decoders-integrations-mappings.json", mappings.get("integration"));
        Assert.assertEquals("/mappings/cti-policies-mappings.json", mappings.get("policy"));
    }

    public void testGetAliasesReturnsExpectedAliases() {
        Map<String, String> aliases = synchronizer.getAliases();

        Assert.assertNotNull(aliases);
        Assert.assertEquals(4, aliases.size());
        Assert.assertEquals(".cti-decoders", aliases.get("decoder"));
        Assert.assertEquals(".cti-kvdbs", aliases.get("kvdb"));
        Assert.assertEquals(".cti-integration-decoders", aliases.get("integration"));
        Assert.assertEquals(".cti-policies", aliases.get("policy"));
    }

    public void testGetIndexNameFormatsCorrectly() {
        String indexName = synchronizer.getIndexName("decoder");

        Assert.assertEquals(
                ".decoders_development_0.0.1-decoders_development_0.0.1-decoder", indexName);
    }
}
