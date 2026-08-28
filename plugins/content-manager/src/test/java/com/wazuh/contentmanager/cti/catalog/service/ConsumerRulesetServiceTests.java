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
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsRequestBuilder;
import org.opensearch.action.admin.indices.exists.indices.IndicesExistsResponse;
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
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.Predicate;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.securityanalytics.action.WIndexDetectorRequest;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
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
    @Mock private SpaceService spaceService;
    @Mock private SecurityAnalyticsService securityAnalyticsService;
    @Mock private UserOverridesService userOverridesService;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
        PluginSettings.getInstance(Settings.EMPTY);
        this.synchronizer =
                new ConsumerRulesetService(
                        this.client,
                        this.consumersIndex,
                        this.environment,
                        this.spaceService,
                        this.securityAnalyticsService,
                        this.userOverridesService);

        // initializeSpaces() runs unconditionally at the top of onSyncComplete(); stub it so tests
        // that don't care about it don't block on awaitResult()'s 60s timeout.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Void>>getArgument(0).onResponse(null);
                            return null;
                        })
                .when(this.spaceService)
                .initializeDefaultSpaces(any());

        // calculateAndUpdate() runs at the end of onSyncComplete() whenever isUpdated is true; stub
        // it the same way so isUpdated=true tests don't block either.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Set<String>>>getArgument(1).onResponse(Collections.emptySet());
                            return null;
                        })
                .when(this.spaceService)
                .calculateAndUpdate(any(), any());

        // syncDetectors() reads the user overrides registry before building any detector request;
        // stub it to "no overrides" so tests that don't care about it don't block on awaitResult()'s
        // 60s timeout.
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<UserOverrides>>getArgument(1)
                                    .onResponse(new UserOverrides(null, null, null));
                            return null;
                        })
                .when(this.userOverridesService)
                .read(any(), any());

        // onSyncComplete() re-applies the user overrides whenever isUpdated is true; stub it the
        // same way so isUpdated=true tests don't block either.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Void>>getArgument(1).onResponse(null);
                            return null;
                        })
                .when(this.userOverridesService)
                .apply(any(), any());
    }

    /**
     * Stubs {@code client.admin().indices().resolveIndex(...)} so {@code indexIsMissing(name)}
     * returns {@code true} only for names accepted by {@code missing}. Same
     * AdminClient/IndicesAdminClient wiring as {@link #testMissingSourceIndices_dataStreamResolved_returnsOnlyMissingOnes},
     * generalized to answer for any index name instead of a fixed pair.
     */
    @SuppressWarnings("unchecked")
    private void mockIndexResolution(Predicate<String> missing) throws Exception {
        AdminClient adminClient = mock(AdminClient.class);
        IndicesAdminClient indicesAdminClient = mock(IndicesAdminClient.class);
        when(this.client.admin()).thenReturn(adminClient);
        when(adminClient.indices()).thenReturn(indicesAdminClient);

        // syncConsumerServices() checks prepareExists(...).get().isExists() before creating each
        // content index; only reached via the full synchronize() path, not onSyncComplete() directly.
        IndicesExistsRequestBuilder existsBuilder = mock(IndicesExistsRequestBuilder.class);
        IndicesExistsResponse existsResponse = mock(IndicesExistsResponse.class);
        when(existsResponse.isExists()).thenReturn(true);
        when(existsBuilder.get()).thenReturn(existsResponse);
        when(indicesAdminClient.prepareExists(any(String[].class))).thenReturn(existsBuilder);

        when(indicesAdminClient.resolveIndex(any(ResolveIndexAction.Request.class)))
                .thenAnswer(
                        invocation -> {
                            ResolveIndexAction.Request request = invocation.getArgument(0);
                            String indexName = request.indices()[0];
                            ResolveIndexAction.Response response = mock(ResolveIndexAction.Response.class);
                            boolean isMissing = missing.test(indexName);
                            when(response.getIndices())
                                    .thenReturn(isMissing ? Collections.emptyList() : Collections.singletonList(null));
                            when(response.getAliases()).thenReturn(Collections.emptyList());
                            when(response.getDataStreams()).thenReturn(Collections.emptyList());
                            ActionFuture<ResolveIndexAction.Response> future = mock(ActionFuture.class);
                            when(future.actionGet()).thenReturn(response);
                            return future;
                        });
    }

    /** Stubs {@code spaceService.getResourcesBySpace(indexName, STANDARD, ..., listener)}. */
    private void mockResourcesBySpace(String indexName, Map<String, Map<String, Object>> result) {
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Map<String, Map<String, Object>>>>getArgument(3)
                                    .onResponse(result);
                            return null;
                        })
                .when(this.spaceService)
                .getResourcesBySpace(eq(indexName), eq(Space.STANDARD), any(), any());
    }

    /** Stubs {@code consumersIndex.getConsumer(...)} to return a ruleset doc with the given pending phases. */
    private void mockExistingConsumerDoc(List<String> pendingPhases) throws Exception {
        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(true);
        StringBuilder phasesJson = new StringBuilder("[");
        for (int i = 0; i < pendingPhases.size(); i++) {
            if (i > 0) {
                phasesJson.append(",");
            }
            phasesJson.append("\"").append(pendingPhases.get(i)).append("\"");
        }
        phasesJson.append("]");
        when(response.getSourceAsString())
                .thenReturn(
                        "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"ready\","
                                + "\"type\":\"cti:catalog:consumer:ruleset\","
                                + "\"resource\":\"\",\"is_public\":true,"
                                + "\"local_offset\":0,\"remote_offset\":0,"
                                + "\"pending_sync_phases\":"
                                + phasesJson
                                + "}");
        when(this.consumersIndex.getConsumer(any())).thenReturn(response);
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
        return spaceService;
    }

    /**
     * Records the engine reload, which is broadcast to every node with {@code
     * ReloadEngineContentAction} rather than built through the space service.
     */
    private void recordEngineReload(List<String> order) {
        doAnswer(
                        invocation -> {
                            order.add("engine");
                            return null;
                        })
                .when(this.client)
                .execute(any(), any(), any());
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

    /** Both collaborators are injected at construction, so a test that stubs them builds its own. */
    private ConsumerRulesetService synchronizerWith(
            SpaceService spaceService, UserOverridesService overridesService) {
        return new ConsumerRulesetService(
                this.client,
                this.consumersIndex,
                this.environment,
                spaceService,
                this.securityAnalyticsService,
                overridesService);
    }

    /**
     * The overrides must be re-applied before the space hash is recalculated and before the space is
     * loaded into the engine, so both see the merged values rather than CTI's raw ones.
     */
    public void testUserOverridesAreAppliedBeforeTheHashAndTheEngineLoad() {
        List<String> order = new java.util.ArrayList<>();
        recordEngineReload(order);
        ConsumerRulesetService service =
                synchronizerWith(stubSpaceServiceRecording(order), stubOverridesServiceRecording(order));

        service.onSyncComplete(true);

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

        ConsumerRulesetService service = synchronizerWith(spaceService, overridesService);

        service.onSyncComplete(true);

        verify(spaceService).calculateAndUpdate(any(), any());
        Assert.assertTrue("the sync must still recalculate the hash", order.contains("hash"));
    }

    /** A sync that changed nothing must not touch the registry. */
    public void testNothingIsAppliedWhenTheSyncChangedNothing() {
        List<String> order = new java.util.ArrayList<>();
        UserOverridesService overridesService = stubOverridesServiceRecording(order);
        ConsumerRulesetService service =
                synchronizerWith(stubSpaceServiceRecording(order), overridesService);

        service.onSyncComplete(false);

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

    /**
     * A partial failure isolated to integrations sets only "integrations" as pending, leaving rules
     * and detectors untouched. securityAnalyticsService stays a plain interface mock here, so
     * syncDetectors() takes its "not a SecurityAnalyticsServiceImpl" early-return path and never
     * interferes with the assertion.
     */
    @SuppressWarnings("unchecked")
    public void testOnSyncComplete_integrationsPartialFailure_setsOnlyIntegrationsPending()
            throws Exception {
        this.mockExistingConsumerDoc(Collections.emptyList());
        this.mockIndexResolution(name -> false);

        Map<String, Map<String, Object>> integrations = new LinkedHashMap<>();
        integrations.put("int-good", Map.of("document", Map.of("name", "good")));
        integrations.put("int-bad", Map.of("document", Map.of("name", "bad")));
        this.mockResourcesBySpace(Constants.INDEX_INTEGRATIONS, integrations);
        this.mockResourcesBySpace(Constants.INDEX_RULES, Collections.emptyMap());

        doAnswer(
                        invocation -> {
                            JsonNode doc = invocation.getArgument(0);
                            ActionListener<?> listener = invocation.getArgument(3);
                            if ("bad".equals(doc.get("name").asText())) {
                                listener.onFailure(new RuntimeException("boom"));
                            } else {
                                listener.onResponse(null);
                            }
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .upsertIntegration(any(), eq(Space.STANDARD), any(), any());

        this.synchronizer.onSyncComplete(true);

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
        Assert.assertEquals(List.of("integrations"), captor.getValue().getPendingSyncPhases());
    }

    /** Symmetric to the integrations case: a rules-only failure sets only "rules" as pending. */
    @SuppressWarnings("unchecked")
    public void testOnSyncComplete_rulesPartialFailure_setsOnlyRulesPending() throws Exception {
        this.mockExistingConsumerDoc(Collections.emptyList());
        this.mockIndexResolution(name -> false);

        this.mockResourcesBySpace(Constants.INDEX_INTEGRATIONS, Collections.emptyMap());
        Map<String, Map<String, Object>> rules = new LinkedHashMap<>();
        rules.put("rule-good", Map.of("document", Map.of("name", "good")));
        rules.put("rule-bad", Map.of("document", Map.of("name", "bad")));
        this.mockResourcesBySpace(Constants.INDEX_RULES, rules);

        doAnswer(
                        invocation -> {
                            JsonNode doc = invocation.getArgument(0);
                            ActionListener<?> listener = invocation.getArgument(3);
                            if ("bad".equals(doc.get("name").asText())) {
                                listener.onFailure(new RuntimeException("boom"));
                            } else {
                                listener.onResponse(null);
                            }
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .upsertRule(any(), eq(Space.STANDARD), any(), any());

        this.synchronizer.onSyncComplete(true);

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
        Assert.assertEquals(List.of("rules"), captor.getValue().getPendingSyncPhases());
    }

    /**
     * missingSourceIndices() aborting the detector push sets "detectors" as pending and never
     * reaches upsertDetectorAsync, without affecting integrations/rules. Requires a
     * SecurityAnalyticsServiceImpl mock (not the plain interface) since syncDetectors() only runs
     * its real logic for that concrete type.
     */
    @SuppressWarnings("unchecked")
    public void testOnSyncComplete_missingSourceIndices_setsDetectorsPending() throws Exception {
        this.mockExistingConsumerDoc(Collections.emptyList());
        // Only the detector's source index is missing; every other resolveIndex() check succeeds.
        this.mockIndexResolution("wazuh-events-v5-test"::equals);

        SecurityAnalyticsServiceImpl sapServiceImpl = mock(SecurityAnalyticsServiceImpl.class);
        ConsumerRulesetService svc =
                new ConsumerRulesetService(
                        this.client,
                        this.consumersIndex,
                        this.environment,
                        this.spaceService,
                        sapServiceImpl,
                        this.userOverridesService);

        Map<String, Map<String, Object>> integrations = new LinkedHashMap<>();
        integrations.put(
                "int-1",
                Map.of(
                        "document",
                        Map.of(
                                "id", "int-1",
                                "metadata", Map.of("title", "Test"),
                                "detector", Map.of("source", List.of("wazuh-events-v5-test")))));
        this.mockResourcesBySpace(Constants.INDEX_INTEGRATIONS, integrations);
        this.mockResourcesBySpace(Constants.INDEX_RULES, Collections.emptyMap());

        doAnswer(
                        invocation -> {
                            ActionListener<?> listener = invocation.getArgument(3);
                            listener.onResponse(null);
                            return null;
                        })
                .when(sapServiceImpl)
                .upsertIntegration(any(), eq(Space.STANDARD), any(), any());
        when(sapServiceImpl.buildDetectorRequest(any(), eq(true), any()))
                .thenReturn(mock(WIndexDetectorRequest.class));

        svc.onSyncComplete(true);

        verify(sapServiceImpl, never()).upsertDetectorAsync(any(), anyBoolean(), any(), any(), any());

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
        Assert.assertEquals(List.of("detectors"), captor.getValue().getPendingSyncPhases());
    }

    /**
     * The core regression test: with isUpdated=false and only "detectors" persisted as pending, the
     * next pass still retries detectors — reading (but not re-pushing) integrations, and never
     * touching rules at all. This is the fix for the permanent-loss bug: today's code skips the
     * whole SAP block whenever isUpdated is false, regardless of what failed last time.
     */
    @SuppressWarnings("unchecked")
    public void testOnSyncComplete_notUpdatedButDetectorsPending_onlyRetriesDetectors()
            throws Exception {
        this.mockExistingConsumerDoc(List.of("detectors"));
        this.mockIndexResolution(name -> false);

        SecurityAnalyticsServiceImpl sapServiceImpl = mock(SecurityAnalyticsServiceImpl.class);
        ConsumerRulesetService svc =
                new ConsumerRulesetService(
                        this.client,
                        this.consumersIndex,
                        this.environment,
                        this.spaceService,
                        sapServiceImpl,
                        this.userOverridesService);

        Map<String, Map<String, Object>> integrations = new LinkedHashMap<>();
        integrations.put(
                "int-1",
                Map.of(
                        "document",
                        Map.of(
                                "id", "int-1",
                                "metadata", Map.of("title", "Test"),
                                "detector", Map.of("source", List.of("wazuh-events-v5-test")))));
        this.mockResourcesBySpace(Constants.INDEX_INTEGRATIONS, integrations);

        when(sapServiceImpl.buildDetectorRequest(any(), eq(true), any()))
                .thenReturn(mock(WIndexDetectorRequest.class));
        doAnswer(
                        invocation -> {
                            ActionListener<?> listener = invocation.getArgument(4);
                            listener.onResponse(null);
                            return null;
                        })
                .when(sapServiceImpl)
                .upsertDetectorAsync(any(), anyBoolean(), any(), any(), any());

        svc.onSyncComplete(false);

        // Integration data was read (detectors need it to build their request) but never pushed.
        verify(this.spaceService)
                .getResourcesBySpace(eq(Constants.INDEX_INTEGRATIONS), eq(Space.STANDARD), any(), any());
        verify(sapServiceImpl, never()).upsertIntegration(any(), any(), any(), any());
        // Rules was never pending and isUpdated is false, so it's not touched at all.
        verify(this.spaceService, never())
                .getResourcesBySpace(eq(Constants.INDEX_RULES), eq(Space.STANDARD), any(), any());
        verify(sapServiceImpl, never()).upsertRule(any(), any(), any(), any());
        verify(sapServiceImpl).upsertDetectorAsync(any(), anyBoolean(), any(), any(), any());

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
        Assert.assertTrue(captor.getValue().getPendingSyncPhases().isEmpty());
    }

    /**
     * When every previously-pending phase succeeds on retry, the persisted list is cleared back to
     * empty.
     */
    @SuppressWarnings("unchecked")
    public void testOnSyncComplete_fullSuccess_clearsPendingPhases() throws Exception {
        this.mockExistingConsumerDoc(List.of("integrations", "rules", "detectors"));
        this.mockIndexResolution(name -> false);

        SecurityAnalyticsServiceImpl sapServiceImpl = mock(SecurityAnalyticsServiceImpl.class);
        ConsumerRulesetService svc =
                new ConsumerRulesetService(
                        this.client,
                        this.consumersIndex,
                        this.environment,
                        this.spaceService,
                        sapServiceImpl,
                        this.userOverridesService);

        Map<String, Map<String, Object>> integrations = new LinkedHashMap<>();
        integrations.put(
                "int-1",
                Map.of(
                        "document",
                        Map.of(
                                "id", "int-1",
                                "metadata", Map.of("title", "Test"),
                                "detector", Map.of("source", List.of("wazuh-events-v5-test")))));
        this.mockResourcesBySpace(Constants.INDEX_INTEGRATIONS, integrations);
        this.mockResourcesBySpace(Constants.INDEX_RULES, Collections.emptyMap());

        doAnswer(
                        invocation -> {
                            ActionListener<?> listener = invocation.getArgument(3);
                            listener.onResponse(null);
                            return null;
                        })
                .when(sapServiceImpl)
                .upsertIntegration(any(), eq(Space.STANDARD), any(), any());
        when(sapServiceImpl.buildDetectorRequest(any(), eq(true), any()))
                .thenReturn(mock(WIndexDetectorRequest.class));
        doAnswer(
                        invocation -> {
                            ActionListener<?> listener = invocation.getArgument(4);
                            listener.onResponse(null);
                            return null;
                        })
                .when(sapServiceImpl)
                .upsertDetectorAsync(any(), anyBoolean(), any(), any(), any());

        svc.onSyncComplete(false);

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex).setConsumer(captor.capture());
        Assert.assertTrue(captor.getValue().getPendingSyncPhases().isEmpty());
    }

    /**
     * With nothing new to sync (isUpdated=false) and nothing pending, onSyncComplete is a true
     * no-op beyond initializeSpaces(): no index reads, no SAP calls, no consumer doc write.
     */
    public void testOnSyncComplete_notUpdatedAndNothingPending_isNoOp() throws Exception {
        this.mockExistingConsumerDoc(Collections.emptyList());

        this.synchronizer.onSyncComplete(false);

        verify(this.consumersIndex, never()).setConsumer(any());
        verify(this.spaceService, never()).getResourcesBySpace(any(), any(), any(), any());
        verifyNoInteractions(this.securityAnalyticsService);
    }

    /**
     * synchronize() calls setConsumerStatus(READY) right after onSyncComplete() on every pass; that
     * status write must preserve pending_sync_phases, not reset it. Drives synchronize() end to end
     * (not onSyncComplete() directly) so the trailing status write is actually exercised.
     */
    @SuppressWarnings("unchecked")
    public void testSynchronize_pendingPhaseSurvivesTrailingStatusWrite() throws Exception {
        this.mockExistingConsumerDoc(List.of("detectors"));
        this.mockIndexResolution(name -> false);

        SecurityAnalyticsServiceImpl sapServiceImpl = mock(SecurityAnalyticsServiceImpl.class);
        ConsumerRulesetService svc =
                new ConsumerRulesetService(
                        this.client,
                        this.consumersIndex,
                        this.environment,
                        this.spaceService,
                        sapServiceImpl,
                        this.userOverridesService);

        // No catalog configured and the offset is already caught up, so syncConsumerServices()
        // reports isUpdated=false — the retry must come entirely from the persisted pending phase.
        ConsumerService consumerService = mock(ConsumerService.class);
        LocalConsumer localConsumer =
                new LocalConsumer(
                        "ctx",
                        "name",
                        "cti:catalog:consumer:ruleset",
                        "",
                        true,
                        LocalConsumer.Status.READY,
                        100L,
                        100L,
                        List.of("detectors"));
        when(consumerService.getLocalConsumer()).thenReturn(localConsumer);
        svc.setConsumerService(consumerService);

        // Detectors fail again on this retry, so onSyncComplete() ends the pass with "detectors"
        // still pending.
        Map<String, Map<String, Object>> integrations = new LinkedHashMap<>();
        integrations.put(
                "int-1",
                Map.of(
                        "document",
                        Map.of(
                                "id", "int-1",
                                "metadata", Map.of("title", "Test"),
                                "detector", Map.of("source", List.of("wazuh-events-v5-test")))));
        this.mockResourcesBySpace(Constants.INDEX_INTEGRATIONS, integrations);
        when(sapServiceImpl.buildDetectorRequest(any(), eq(true), any()))
                .thenReturn(mock(WIndexDetectorRequest.class));
        doAnswer(
                        invocation -> {
                            ActionListener<?> listener = invocation.getArgument(4);
                            listener.onFailure(new RuntimeException("still broken"));
                            return null;
                        })
                .when(sapServiceImpl)
                .upsertDetectorAsync(any(), anyBoolean(), any(), any(), any());

        svc.synchronize();

        ArgumentCaptor<LocalConsumer> captor = ArgumentCaptor.forClass(LocalConsumer.class);
        verify(this.consumersIndex, org.mockito.Mockito.atLeastOnce()).setConsumer(captor.capture());
        LocalConsumer lastWrite = captor.getValue();
        Assert.assertEquals(LocalConsumer.Status.READY, lastWrite.getStatus());
        Assert.assertEquals(List.of("detectors"), lastWrite.getPendingSyncPhases());
    }
}
