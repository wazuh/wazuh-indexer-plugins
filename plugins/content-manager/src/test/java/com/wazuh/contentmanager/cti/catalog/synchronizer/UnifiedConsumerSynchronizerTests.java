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
package com.wazuh.contentmanager.cti.catalog.synchronizer;

import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

/** Tests for the UnifiedConsumerSynchronizer class. */
public class UnifiedConsumerSynchronizerTests extends OpenSearchTestCase {

    private UnifiedConsumerSynchronizer synchronizer;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);
        this.synchronizer =
                new UnifiedConsumerSynchronizer(this.client, this.consumersIndex, this.environment);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    /** Tests that getContext returns the expected context value. */
    public void testGetContextReturnsExpectedValue() {
        String context = this.synchronizer.getContext();

        Assert.assertEquals(PluginSettings.getInstance().getContentContext(), context);
    }

    /** Tests that getConsumer returns the expected consumer value. */
    public void testGetConsumerReturnsExpectedValue() {
        String consumer = this.synchronizer.getConsumer();

        Assert.assertEquals(PluginSettings.getInstance().getContentConsumer(), consumer);
    }

    /** Tests that getMappings returns the expected index mappings. */
    public void testGetMappingsReturnsExpectedMappings() {
        Map<String, String> mappings = this.synchronizer.getMappings();

        Assert.assertNotNull(mappings);
        Assert.assertEquals(6, mappings.size());
        Assert.assertEquals("/mappings/cti-rules-mappings.json", mappings.get("rule"));
        Assert.assertEquals("/mappings/cti-decoders-mappings.json", mappings.get("decoder"));
        Assert.assertEquals("/mappings/cti-kvdbs-mappings.json", mappings.get("kvdb"));
        Assert.assertEquals("/mappings/cti-integrations-mappings.json", mappings.get("integration"));
        Assert.assertEquals("/mappings/cti-policies-mappings.json", mappings.get("policy"));
        Assert.assertEquals("/mappings/engine-filters-mappings.json", mappings.get("filters"));
    }

    /** Tests that getAliases returns empty map as aliases are used as names. */
    public void testGetAliasesReturnsEmpty() {
        Map<String, String> aliases = this.synchronizer.getAliases();
        Assert.assertNotNull(aliases);
        Assert.assertTrue(aliases.isEmpty());
    }

    /** Tests that getIndexName returns the correct unified name. */
    public void testGetIndexNameFormatsCorrectly() {
        Assert.assertEquals(".cti-rules", this.synchronizer.getIndexName("rule"));
        Assert.assertEquals(".cti-decoders", this.synchronizer.getIndexName("decoder"));
        Assert.assertEquals(".cti-kvdbs", this.synchronizer.getIndexName("kvdb"));
        Assert.assertEquals(".cti-integrations", this.synchronizer.getIndexName("integration"));
        Assert.assertEquals(".cti-policies", this.synchronizer.getIndexName("policy"));
    }

    public void testGetIndexNameReturnsErrorOnInvalidType() {
        Exception exception =
                expectThrows(
                        IllegalArgumentException.class,
                        () -> {
                            this.synchronizer.getIndexName("invalid_resource");
                        });

        String expectedMessage = "Unknown type: invalid_resource";
        String actualMessage = exception.getMessage();

        Assert.assertTrue(actualMessage.contains(expectedMessage));
    }
}
