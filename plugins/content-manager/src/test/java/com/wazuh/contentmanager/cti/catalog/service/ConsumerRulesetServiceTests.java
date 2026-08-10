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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.lucene.tests.util.LuceneTestCase;
import org.opensearch.action.admin.indices.resolve.ResolveIndexAction;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.action.ActionFuture;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.env.Environment;
import org.opensearch.index.IndexNotFoundException;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.AdminClient;
import org.opensearch.transport.client.Client;
import org.opensearch.transport.client.IndicesAdminClient;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/** Tests for the UnifiedConsumerSynchronizer class. */
public class ConsumerRulesetServiceTests extends OpenSearchTestCase {

    private ConsumerRulesetService synchronizer;
    private AutoCloseable closeable;

    @Mock private Client client;
    @Mock private ConsumersIndex consumersIndex;
    @Mock private Environment environment;
    @Mock private EngineService engineService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);
        this.synchronizer =
                new ConsumerRulesetService(
                        this.client, this.consumersIndex, this.environment, this.engineService);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        if (this.closeable != null) {
            this.closeable.close();
        }
        super.tearDown();
    }

    // --- User overrides registry -------------------------------------------------------------

    /**
     * Wires a {@link SpaceService} whose async calls answer immediately, recording the order in which
     * the interesting ones happen. Without this the real service would sit on {@code awaitResult}'s
     * 60-second timeout for every call.
     */
    private SpaceService stubSpaceServiceRecording(List<String> order) {
        SpaceService spaceService = mock(SpaceService.class);

        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Void>>getArgument(0).onResponse(null);
                            return null;
                        })
                .when(spaceService)
                .initializeDefaultSpaces(any());
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Map<String, Map<String, Object>>>>getArgument(3)
                                    .onResponse(Collections.emptyMap());
                            return null;
                        })
                .when(spaceService)
                .getResourcesBySpace(any(), any(), any(), any());
        doAnswer(
                        invocation -> {
                            order.add("hash");
                            invocation
                                    .<ActionListener<Set<String>>>getArgument(1)
                                    .onResponse(Collections.emptySet());
                            return null;
                        })
                .when(spaceService)
                .calculateAndUpdate(any(), any());
        doAnswer(
                        invocation -> {
                            order.add("engine");
                            invocation
                                    .<ActionListener<JsonNode>>getArgument(1)
                                    .onResponse(new ObjectMapper().createObjectNode());
                            return null;
                        })
                .when(spaceService)
                .buildEnginePayload(any(), any());

        return spaceService;
    }

    /** A {@link UserOverridesService} whose apply succeeds, recording when it ran. */
    private UserOverridesService stubOverridesServiceRecording(List<String> order) {
        UserOverridesService overridesService = mock(UserOverridesService.class);
        doAnswer(
                        invocation -> {
                            order.add("apply");
                            invocation.<ActionListener<Void>>getArgument(1).onResponse(null);
                            return null;
                        })
                .when(overridesService)
                .apply(any(), any());
        return overridesService;
    }

    /**
     * The overrides must be re-applied before the space hash is recalculated and before the space is
     * loaded into the engine, so both see the merged values rather than CTI's raw ones.
     */
    public void testUserOverridesAreAppliedBeforeTheHashAndTheEngineLoad() {
        List<String> order = new java.util.ArrayList<>();
        this.synchronizer.setSpaceService(stubSpaceServiceRecording(order));
        this.synchronizer.setUserOverridesService(stubOverridesServiceRecording(order));

        this.synchronizer.onSyncComplete(true);

        Assert.assertEquals("the overrides must be applied first", "apply", order.get(0));
        Assert.assertTrue(
                "the space hash must be recalculated after the merge",
                order.indexOf("apply") < order.indexOf("hash"));
        Assert.assertTrue(
                "the engine must be loaded after the merge",
                order.indexOf("apply") < order.indexOf("engine"));
    }

    /**
     * A failure to apply the overrides is logged and the synchronization continues. The registry is
     * durable, so the next sync retries; aborting here would leave the space half-built.
     */
    public void testSyncContinuesWhenApplyingOverridesFails() {
        List<String> order = new java.util.ArrayList<>();
        SpaceService spaceService = stubSpaceServiceRecording(order);
        UserOverridesService overridesService = mock(UserOverridesService.class);
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Void>>getArgument(1)
                                    .onFailure(new java.io.IOException("registry unavailable"));
                            return null;
                        })
                .when(overridesService)
                .apply(any(), any());

        this.synchronizer.setSpaceService(spaceService);
        this.synchronizer.setUserOverridesService(overridesService);

        this.synchronizer.onSyncComplete(true);

        verify(spaceService).calculateAndUpdate(any(), any());
        Assert.assertTrue("the sync must still recalculate the hash", order.contains("hash"));
    }

    /** A sync that changed nothing must not touch the registry. */
    public void testNothingIsAppliedWhenTheSyncChangedNothing() {
        List<String> order = new java.util.ArrayList<>();
        UserOverridesService overridesService = stubOverridesServiceRecording(order);
        this.synchronizer.setSpaceService(stubSpaceServiceRecording(order));
        this.synchronizer.setUserOverridesService(overridesService);

        this.synchronizer.onSyncComplete(false);

        verify(overridesService, never()).apply(any(), any());
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
    }

    /** Tests that getIndexName returns the correct unified name. */
    public void testGetIndexNameFormatsCorrectly() {
        Assert.assertEquals("wazuh-threatintel-rules", this.synchronizer.getIndexName("rule"));
        Assert.assertEquals("wazuh-threatintel-decoders", this.synchronizer.getIndexName("decoder"));
        Assert.assertEquals("wazuh-threatintel-kvdbs", this.synchronizer.getIndexName("kvdb"));
        Assert.assertEquals(
                "wazuh-threatintel-integrations", this.synchronizer.getIndexName("integration"));
        Assert.assertEquals("wazuh-threatintel-policies", this.synchronizer.getIndexName("policy"));
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
     * missingSourceIndices() collects the detector source indices from the integration documents and
     * returns only those missing from the cluster. Source indices are usually data streams
     * (wazuh-events-v5-*), so resolution must be data-stream-aware: a name that resolves to a data
     * stream is NOT missing, and an unresolvable name is missing.
     */
    @SuppressWarnings("unchecked")
    public void testMissingSourceIndices_dataStreamResolved_returnsOnlyMissingOnes()
            throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode doc1 =
                mapper.readTree(
                        "{\"detector\":{\"source\":[\"wazuh-events-v5-security\",\"wazuh-events-v5-other\"]}}");
        JsonNode doc2 = mapper.readTree("{\"detector\":{\"source\":[\"wazuh-events-v5-security\"]}}");

        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        when(this.client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);

        // wazuh-events-v5-security exists as a data stream (no plain index, no alias).
        ResolveIndexAction.Response dataStreamResponse = mock(ResolveIndexAction.Response.class);
        when(dataStreamResponse.getIndices()).thenReturn(Collections.emptyList());
        when(dataStreamResponse.getAliases()).thenReturn(Collections.emptyList());
        when(dataStreamResponse.getDataStreams()).thenReturn(Collections.singletonList(null));
        ActionFuture<ResolveIndexAction.Response> dataStreamFuture = mock(ActionFuture.class);
        when(dataStreamFuture.actionGet()).thenReturn(dataStreamResponse);

        when(indicesAdminClient.resolveIndex(any(ResolveIndexAction.Request.class)))
                .thenAnswer(
                        invocation -> {
                            ResolveIndexAction.Request request = invocation.getArgument(0);
                            if ("wazuh-events-v5-security".equals(request.indices()[0])) {
                                return dataStreamFuture;
                            }
                            throw new IndexNotFoundException(request.indices()[0]);
                        });

        List<String> missing = this.synchronizer.missingSourceIndices(List.of(doc1, doc2));

        Assert.assertEquals(List.of("wazuh-events-v5-other"), missing);
    }

    /** A name resolving to a plain index (e.g. a state index) is not reported as missing. */
    @SuppressWarnings("unchecked")
    public void testMissingSourceIndices_plainIndexResolved_returnsEmpty() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode doc = mapper.readTree("{\"detector\":{\"source\":[\"wazuh-states-sca\"]}}");

        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        when(this.client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);

        ResolveIndexAction.Response indexResponse = mock(ResolveIndexAction.Response.class);
        when(indexResponse.getIndices()).thenReturn(Collections.singletonList(null));
        when(indexResponse.getAliases()).thenReturn(Collections.emptyList());
        when(indexResponse.getDataStreams()).thenReturn(Collections.emptyList());
        ActionFuture<ResolveIndexAction.Response> future = mock(ActionFuture.class);
        when(future.actionGet()).thenReturn(indexResponse);
        when(indicesAdminClient.resolveIndex(any(ResolveIndexAction.Request.class))).thenReturn(future);

        List<String> missing = this.synchronizer.missingSourceIndices(List.of(doc));

        Assert.assertTrue(missing.isEmpty());
    }

    /** Documents without a detector.source array contribute nothing; no cluster calls are made. */
    public void testMissingSourceIndices_noDetectorSource_returnsEmpty() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        JsonNode doc = mapper.readTree("{\"metadata\":{\"title\":\"no detector here\"}}");

        List<String> missing = this.synchronizer.missingSourceIndices(List.of(doc));

        Assert.assertTrue(missing.isEmpty());
        verifyNoInteractions(this.client);
    }

    /**
     * synchronize() must transition the consumer to FAILED — not leave it stuck at RUNNING — when an
     * unexpected exception is thrown mid-sync, and must rethrow so CatalogSyncJob's existing
     * log-and-continue catch still fires for the next synchronizer in the list.
     */
    public void testSynchronize_unexpectedException_setsFailedStatusAndRethrows() throws Exception {
        GetResponse existingConsumerResponse = mock(GetResponse.class);
        when(existingConsumerResponse.isExists()).thenReturn(true);
        when(existingConsumerResponse.getSourceAsString())
                .thenReturn(
                        "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"ready\","
                                + "\"type\":\"cti:catalog:consumer:ruleset\","
                                + "\"resource\":\"\",\"is_public\":true,"
                                + "\"local_offset\":0,\"remote_offset\":0}");
        when(this.consumersIndex.getConsumer(any())).thenReturn(existingConsumerResponse);

        ConsumerService failingConsumerService = mock(ConsumerService.class);
        when(failingConsumerService.getLocalConsumer())
                .thenThrow(new RuntimeException("Cluster unavailable"));
        this.synchronizer.setConsumerService(failingConsumerService);

        LuceneTestCase.expectThrows(RuntimeException.class, this.synchronizer::synchronize);

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex, org.mockito.Mockito.atLeastOnce()).setConsumer(captor.capture());
        LocalConsumer lastWrite = captor.getValue();
        Assert.assertEquals(LocalConsumer.Status.FAILED, lastWrite.getStatus());
    }
}
