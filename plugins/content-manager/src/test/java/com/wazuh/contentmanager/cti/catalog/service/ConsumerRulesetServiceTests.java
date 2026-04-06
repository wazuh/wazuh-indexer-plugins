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
package com.wazuh.contentmanager.cti.catalog.service;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

/** Tests for the ConsumerRulesetService class. */
public class ConsumerRulesetServiceTests extends OpenSearchTestCase {

    private ConsumerRulesetService synchronizer;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;
    @Mock private EngineService engineService;
    @Mock private SpaceService spaceService;
    @Mock private SecurityAnalyticsServiceImpl securityAnalyticsService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);
        this.synchronizer =
                new ConsumerRulesetService(
                        this.client, this.consumersIndex, this.environment, this.engineService);
        this.synchronizer.setSpaceService(this.spaceService);
        this.synchronizer.setSecurityAnalyticsService(this.securityAnalyticsService);
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
                LuceneTestCase.expectThrows(
                        IllegalArgumentException.class,
                        () -> {
                            this.synchronizer.getIndexName("invalid_resource");
                        });

        String expectedMessage = "Unknown type: invalid_resource";
        String actualMessage = exception.getMessage();

        Assert.assertTrue(actualMessage.contains(expectedMessage));
    }

    /**
     * When a LocalConsumer document exists for the current context/consumer, no cleanup should
     * happen.
     */
    public void testCleanupSkippedWhenConsumerDocExists()
            throws ExecutionException, InterruptedException, TimeoutException {
        GetResponse existingDoc = mock(GetResponse.class);
        when(existingDoc.isExists()).thenReturn(true);
        when(this.consumersIndex.getConsumer(any(), any())).thenReturn(existingDoc);

        this.synchronizer.cleanupStandardSpaceIfConsumerChanged();

        verifyNoInteractions(this.spaceService);
        verifyNoInteractions(this.securityAnalyticsService);
    }

    /**
     * When no LocalConsumer document exists but the Standard space has no resources, no cleanup
     * should happen.
     */
    public void testCleanupSkippedWhenNoResourcesExist() throws Exception {
        GetResponse missingDoc = mock(GetResponse.class);
        when(missingDoc.isExists()).thenReturn(false);
        when(this.consumersIndex.getConsumer(any(), any())).thenReturn(missingDoc);

        Map<String, Map<String, String>> emptyResources = new HashMap<>();
        emptyResources.put(Constants.KEY_RULES, Collections.emptyMap());
        emptyResources.put(Constants.KEY_INTEGRATIONS, Collections.emptyMap());
        when(this.spaceService.getSpaceResources(Space.STANDARD.toString())).thenReturn(emptyResources);

        this.synchronizer.cleanupStandardSpaceIfConsumerChanged();

        verify(this.spaceService).getSpaceResources(Space.STANDARD.toString());
        verify(this.spaceService, never()).resetSpace(any(), any());
    }

    /**
     * When no LocalConsumer document exists and the Standard space has resources, the cleanup should
     * delegate to SpaceService.resetSpace to delete SAP resources and index documents.
     */
    public void testCleanupResetsSpaceWhenConsumerChanged() throws Exception {
        GetResponse missingDoc = mock(GetResponse.class);
        when(missingDoc.isExists()).thenReturn(false);
        when(this.consumersIndex.getConsumer(any(), any())).thenReturn(missingDoc);

        Map<String, Map<String, String>> resources = new HashMap<>();
        Map<String, String> rules = new HashMap<>();
        rules.put("rule-1", "hash1");
        resources.put(Constants.KEY_RULES, rules);
        when(this.spaceService.getSpaceResources(Space.STANDARD.toString())).thenReturn(resources);

        this.synchronizer.cleanupStandardSpaceIfConsumerChanged();

        verify(this.spaceService).resetSpace(eq(Space.STANDARD), eq(this.securityAnalyticsService));
    }

    /**
     * When resetSpace throws an IOException, the cleanup should catch it and not propagate, allowing
     * the sync to proceed.
     */
    public void testCleanupHandlesResetSpaceFailure() throws Exception {
        GetResponse missingDoc = mock(GetResponse.class);
        when(missingDoc.isExists()).thenReturn(false);
        when(this.consumersIndex.getConsumer(any(), any())).thenReturn(missingDoc);

        Map<String, Map<String, String>> resources = new HashMap<>();
        Map<String, String> integrations = new HashMap<>();
        integrations.put("integration-1", "hash1");
        resources.put(Constants.KEY_INTEGRATIONS, integrations);
        when(this.spaceService.getSpaceResources(Space.STANDARD.toString())).thenReturn(resources);
        doThrow(new IOException("Bulk deletion failed"))
                .when(this.spaceService)
                .resetSpace(eq(Space.STANDARD), any());

        // Should not throw
        this.synchronizer.cleanupStandardSpaceIfConsumerChanged();
    }

    /**
     * When getConsumer() throws an exception, the cleanup should log the error and not propagate it,
     * allowing the sync to proceed.
     */
    public void testCleanupHandlesConsumerIndexException()
            throws ExecutionException, InterruptedException, TimeoutException {
        when(this.consumersIndex.getConsumer(any(), any()))
                .thenThrow(new RuntimeException("Index not ready"));

        // Should not throw
        this.synchronizer.cleanupStandardSpaceIfConsumerChanged();

        verify(this.spaceService, never()).getSpaceResources(any());
    }
}
