/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.transport;

import org.apache.lucene.search.TotalHits;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.get.GetRequest;
import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.get.GetResult;
import org.opensearch.search.SearchHit;
import org.opensearch.search.SearchHits;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/** Unit tests for {@link SpaceClearer}. */
public class SpaceClearerTests extends OpenSearchTestCase {

    private static final String POLICY_DOC_ID = "draft-policy-doc";
    private static final Set<String> NORMALIZATION_FIELDS =
            Set.of(Constants.KEY_DECODERS, Constants.KEY_KVDBS);

    private Client client;
    private IntegrationService integrationService;
    private SecurityAnalyticsService securityAnalyticsService;
    private SpaceService spaceService;

    @Before
    @Override
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(Settings.EMPTY);
        this.client = mock(Client.class);
        this.integrationService = mock(IntegrationService.class);
        this.securityAnalyticsService = mock(SecurityAnalyticsService.class);
        this.spaceService = mock(SpaceService.class);

        // SpaceService bulk delete + hash recompute succeed by default. The delete reports that it
        // removed something (true) so the normal path recomputes the hash; no-op tests override this.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Boolean>>getArgument(2).onResponse(true);
                            return null;
                        })
                .when(this.spaceService)
                .deleteSpaceResources(any(Space.class), anyList(), any());
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Set<String>>>getArgument(1)
                                    .onResponse(Collections.emptySet());
                            return null;
                        })
                .when(this.spaceService)
                .calculateAndUpdate(anyList(), any());

        // Client policy store so PolicyLinks.unlink completes for a deleted integration.
        ThreadContext threadContext = new ThreadContext(Settings.EMPTY);
        ThreadPool threadPool = mock(ThreadPool.class);
        when(threadPool.getThreadContext()).thenReturn(threadContext);
        // The log-type-delete retry schedules itself; run it immediately in tests.
        doAnswer(
                        invocation -> {
                            ((Runnable) invocation.getArgument(0)).run();
                            return null;
                        })
                .when(threadPool)
                .schedule(any(Runnable.class), any(TimeValue.class), anyString());
        when(this.client.threadPool()).thenReturn(threadPool);
        doAnswer(
                        invocation -> {
                            SearchResponse response = mock(SearchResponse.class);
                            SearchHit[] hits = {
                                new SearchHit(0, POLICY_DOC_ID, Collections.emptyMap(), Collections.emptyMap())
                            };
                            when(response.getHits())
                                    .thenReturn(
                                            new SearchHits(hits, new TotalHits(1, TotalHits.Relation.EQUAL_TO), 0.0f));
                            invocation.<ActionListener<SearchResponse>>getArgument(1).onResponse(response);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any());
        doAnswer(
                        invocation -> {
                            String source =
                                    "{\"document\":{\"id\":\"p\",\"integrations\":[\"A\"]},"
                                            + "\"hash\":{\"sha256\":\"old\"},\"space\":{\"name\":\"draft\"}}";
                            invocation
                                    .<ActionListener<GetResponse>>getArgument(1)
                                    .onResponse(
                                            new GetResponse(
                                                    new GetResult(
                                                            Constants.INDEX_POLICIES,
                                                            POLICY_DOC_ID,
                                                            1L,
                                                            1L,
                                                            2L,
                                                            true,
                                                            new BytesArray(source),
                                                            Collections.emptyMap(),
                                                            Collections.emptyMap())));
                            return null;
                        })
                .when(this.client)
                .get(any(GetRequest.class), any());
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<IndexResponse>>getArgument(1)
                                    .onResponse(mock(IndexResponse.class));
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any());

        // IntegrationService + SA: list and delete are satisfied immediately.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Void>>getArgument(1).onResponse(null);
                            return null;
                        })
                .when(this.integrationService)
                .deleteIntegrationDocAsync(any(), any());
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Object>>getArgument(2).onResponse(null);
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .deleteIntegration(any(), any(), any());
    }

    @SuppressWarnings("unchecked")
    private void stubList(List<String> integrationIds) {
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<List<String>>>getArgument(1).onResponse(integrationIds);
                            return null;
                        })
                .when(this.integrationService)
                .listIntegrationIdsAsync(any(), any());
    }

    @SuppressWarnings("unchecked")
    private void stubRuleIds(List<String> ruleIds) {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Map<String, List<String>>>>getArgument(2)
                                    .onResponse(Map.of(Constants.KEY_RULES, ruleIds));
                            return null;
                        })
                .when(this.spaceService)
                .getSpaceResourceIdsAsync(any(), any(), any());
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Object>>getArgument(2).onResponse(null);
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .deleteRule(any(), any(), any());
    }

    @SuppressWarnings("unchecked")
    private void stubEmptyResults(Map<String, IntegrationService.EmptyResult> byId) {
        doAnswer(
                        invocation -> {
                            String id = invocation.getArgument(0);
                            invocation
                                    .<ActionListener<IntegrationService.EmptyResult>>getArgument(2)
                                    .onResponse(byId.get(id));
                            return null;
                        })
                .when(this.integrationService)
                .emptyFieldsAsync(any(), any(), any());
    }

    private boolean runReconcile(Set<String> clearedFields) {
        AtomicReference<Boolean> done = new AtomicReference<>(false);
        AtomicReference<Exception> failure = new AtomicReference<>();
        SpaceClearer.reconcileEmptyIntegrations(
                this.client,
                this.integrationService,
                this.securityAnalyticsService,
                Space.DRAFT.toString(),
                clearedFields,
                ActionListener.wrap(v -> done.set(true), failure::set));
        if (failure.get() != null) {
            fail(failure.get().getMessage());
        }
        return done.get();
    }

    /** Only the integrations left empty are deleted; the ones still holding resources are kept. */
    public void testReconcileEmptyIntegrations_deletesOnlyThoseLeftEmpty() {
        this.stubList(List.of("A", "B"));
        Map<String, IntegrationService.EmptyResult> results = new HashMap<>();
        results.put("A", new IntegrationService.EmptyResult(false, true, true)); // empty, not protected
        results.put(
                "B", new IntegrationService.EmptyResult(false, false, false)); // still has resources
        this.stubEmptyResults(results);

        assertTrue(this.runReconcile(NORMALIZATION_FIELDS));

        verify(this.integrationService).deleteIntegrationDocAsync(eq("A"), any());
        verify(this.integrationService, never()).deleteIntegrationDocAsync(eq("B"), any());
        verify(this.securityAnalyticsService).deleteIntegration(eq("A"), eq(Space.DRAFT), any());
        verify(this.securityAnalyticsService, never()).deleteIntegration(eq("B"), any(), any());
    }

    /** A protected integration left empty is never deleted. */
    public void testReconcileEmptyIntegrations_skipsProtected() {
        this.stubList(List.of("A"));
        this.stubEmptyResults(
                Map.of("A", new IntegrationService.EmptyResult(true, true, true))); // protected, empty

        assertTrue(this.runReconcile(NORMALIZATION_FIELDS));

        verify(this.integrationService, never()).deleteIntegrationDocAsync(any(), any());
        verify(this.securityAnalyticsService, never()).deleteIntegration(any(), any(), any());
    }

    /** No integrations in the space: the reconciliation is a no-op that still completes. */
    public void testReconcileEmptyIntegrations_noIntegrationsIsNoop() {
        this.stubList(List.of());

        assertTrue(this.runReconcile(NORMALIZATION_FIELDS));

        verify(this.integrationService, never()).emptyFieldsAsync(any(), any(), any());
        verify(this.integrationService, never()).deleteIntegrationDocAsync(any(), any());
    }

    /**
     * When Security Analytics transiently reports that the integration still has active rules, the
     * log-type delete is retried and the integration is removed without the caller re-running.
     */
    @SuppressWarnings("unchecked")
    public void testReconcileEmptyIntegrations_retriesActiveRulesConflictThenDeletes() {
        this.stubList(List.of("A"));
        this.stubEmptyResults(Map.of("A", new IntegrationService.EmptyResult(false, true, true)));
        AtomicReference<Integer> calls = new AtomicReference<>(0);
        doAnswer(
                        invocation -> {
                            int n = calls.get() + 1;
                            calls.set(n);
                            ActionListener<Object> l = invocation.getArgument(2);
                            if (n == 1) {
                                l.onFailure(
                                        new OpenSearchStatusException(
                                                "Log Type with id A cannot be deleted because active rules exist",
                                                RestStatus.BAD_REQUEST));
                            } else {
                                l.onResponse(null);
                            }
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .deleteIntegration(eq("A"), any(), any());

        assertTrue(this.runReconcile(NORMALIZATION_FIELDS));

        verify(this.securityAnalyticsService, times(2)).deleteIntegration(eq("A"), any(), any());
        verify(this.integrationService).deleteIntegrationDocAsync(eq("A"), any());
    }

    private Exception runClearNormalization() {
        AtomicReference<Boolean> done = new AtomicReference<>(false);
        AtomicReference<Exception> failure = new AtomicReference<>();
        SpaceClearer.clearNormalization(
                this.client,
                this.spaceService,
                this.integrationService,
                this.securityAnalyticsService,
                Space.DRAFT.toString(),
                ActionListener.wrap(v -> done.set(true), failure::set));
        assertTrue("listener must be notified", done.get() || failure.get() != null);
        return failure.get();
    }

    /** clearNormalization wipes only decoders/kvdbs/filters and recomputes the space hash. */
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void testClearNormalization_deletesNormalizationAndRecomputesHash() {
        this.stubList(List.of());

        assertNull(this.runClearNormalization());

        ArgumentCaptor<List> indices = ArgumentCaptor.forClass(List.class);
        verify(this.spaceService).deleteSpaceResources(eq(Space.DRAFT), indices.capture(), any());
        List<String> deleted = indices.getValue();
        assertTrue(deleted.contains(Constants.INDEX_DECODERS));
        assertTrue(deleted.contains(Constants.INDEX_KVDBS));
        assertTrue(deleted.contains(Constants.INDEX_FILTERS));
        assertFalse("rules are detection, not touched", deleted.contains(Constants.INDEX_RULES));
        assertFalse(
                "integrations are reconciled, not bulk-deleted",
                deleted.contains(Constants.INDEX_INTEGRATIONS));
        verify(this.spaceService).calculateAndUpdate(eq(List.of(Space.DRAFT.toString())), any());
    }

    /**
     * A no-op clear (nothing deleted or unlinked) completes but leaves the hash untouched: the
     * recompute is skipped entirely (issue #1722's no-op requirement).
     */
    @SuppressWarnings("unchecked")
    public void testClearNormalization_onEmptyDraftSkipsHashRecompute() {
        this.stubList(List.of());
        // Nothing to delete: the bulk reports it removed no documents, and the policy's root decoder
        // and filters are already empty (served by the default policy get), so no step changes state.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Boolean>>getArgument(2).onResponse(false);
                            return null;
                        })
                .when(this.spaceService)
                .deleteSpaceResources(any(Space.class), anyList(), any());

        assertNull(this.runClearNormalization());

        verify(this.integrationService, never()).emptyFieldsAsync(any(), any(), any());
        verify(this.spaceService, never()).calculateAndUpdate(any(), any());
    }

    /** A failure is propagated (never swallowed), and a re-run after the fault converges. */
    @SuppressWarnings("unchecked")
    public void testClearNormalization_failurePropagatesAndRerunSucceeds() {
        this.stubList(List.of());
        // First run: the bulk delete fails.
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Boolean>>getArgument(2)
                                    .onFailure(new IllegalStateException("boom"));
                            return null;
                        })
                .when(this.spaceService)
                .deleteSpaceResources(any(Space.class), anyList(), any());

        Exception failure = this.runClearNormalization();
        assertNotNull("the failure must not be swallowed", failure);

        // Second run: the transient fault is gone and the clear converges.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Boolean>>getArgument(2).onResponse(true);
                            return null;
                        })
                .when(this.spaceService)
                .deleteSpaceResources(any(Space.class), anyList(), any());

        assertNull(this.runClearNormalization());
    }

    private Exception runClearDetection() {
        AtomicReference<Boolean> done = new AtomicReference<>(false);
        AtomicReference<Exception> failure = new AtomicReference<>();
        SpaceClearer.clearDetection(
                this.client,
                this.spaceService,
                this.integrationService,
                this.securityAnalyticsService,
                Space.DRAFT.toString(),
                ActionListener.wrap(v -> done.set(true), failure::set));
        assertTrue("listener must be notified", done.get() || failure.get() != null);
        return failure.get();
    }

    /** clearDetection deletes rules (index + Security Analytics) and leaves normalization alone. */
    @SuppressWarnings({"unchecked", "rawtypes"})
    public void testClearDetection_deletesRulesKeepsNormalization() {
        this.stubRuleIds(List.of("r1"));
        this.stubList(List.of());

        assertNull(this.runClearDetection());

        verify(this.securityAnalyticsService).deleteRule(eq("r1"), eq(Space.DRAFT), any());
        ArgumentCaptor<List> indices = ArgumentCaptor.forClass(List.class);
        verify(this.spaceService).deleteSpaceResources(eq(Space.DRAFT), indices.capture(), any());
        List<String> deleted = indices.getValue();
        assertEquals(List.of(Constants.INDEX_RULES), deleted);
        assertFalse(
                "decoders are normalization, not touched", deleted.contains(Constants.INDEX_DECODERS));
        verify(this.spaceService).calculateAndUpdate(eq(List.of(Space.DRAFT.toString())), any());
    }

    /**
     * With no rules and nothing to reconcile, clearDetection completes and skips the hash recompute.
     */
    @SuppressWarnings("unchecked")
    public void testClearDetection_noRulesSkipsHashRecompute() {
        this.stubRuleIds(List.of());
        this.stubList(List.of());
        // Nothing to delete: the bulk reports it removed no documents.
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Boolean>>getArgument(2).onResponse(false);
                            return null;
                        })
                .when(this.spaceService)
                .deleteSpaceResources(any(Space.class), anyList(), any());

        assertNull(this.runClearDetection());

        verify(this.securityAnalyticsService, never()).deleteRule(any(), any(), any());
        verify(this.spaceService, never()).calculateAndUpdate(any(), any());
    }

    /**
     * clearDetection deletes the rule documents LAST: if the integration reconcile fails, the rule
     * documents must survive (not be bulk-deleted) so a re-run can re-find them and finish the
     * Security Analytics cleanup. Otherwise the clear could never converge after a partial failure.
     */
    @SuppressWarnings("unchecked")
    public void testClearDetection_reconcileFailureKeepsRuleDocsForRerun() {
        this.stubRuleIds(List.of("r1"));
        // Reconcile fails before the rule documents are deleted: listing the integrations errors out.
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<List<String>>>getArgument(1)
                                    .onFailure(new IllegalStateException("boom"));
                            return null;
                        })
                .when(this.integrationService)
                .listIntegrationIdsAsync(any(), any());

        Exception failure = this.runClearDetection();
        assertNotNull("the reconcile failure must propagate", failure);

        // The rule documents must NOT have been deleted, so a re-run re-finds them.
        verify(this.spaceService, never()).deleteSpaceResources(any(Space.class), anyList(), any());
        verify(this.spaceService, never()).calculateAndUpdate(any(), any());
    }

    private static OpenSearchStatusException notFound() {
        return new OpenSearchStatusException("not found", RestStatus.NOT_FOUND);
    }

    private Exception runReconcileCapture(Set<String> clearedFields) {
        AtomicReference<Boolean> done = new AtomicReference<>(false);
        AtomicReference<Exception> failure = new AtomicReference<>();
        SpaceClearer.reconcileEmptyIntegrations(
                this.client,
                this.integrationService,
                this.securityAnalyticsService,
                Space.DRAFT.toString(),
                clearedFields,
                ActionListener.wrap(v -> done.set(true), failure::set));
        assertTrue("listener must be notified", done.get() || failure.get() != null);
        return failure.get();
    }

    /**
     * The integration document is deleted LAST: if the policy unlink fails, the document survives so
     * a re-run can re-find and reconcile the integration (no dangling policy reference).
     */
    @SuppressWarnings("unchecked")
    public void testReconcileEmptyIntegrations_unlinkFailureKeepsDocumentForRerun() {
        this.stubList(List.of("A"));
        this.stubEmptyResults(Map.of("A", new IntegrationService.EmptyResult(false, true, true)));
        // Make the policy unlink fail: the policy document cannot be found.
        doAnswer(
                        invocation -> {
                            SearchResponse response = mock(SearchResponse.class);
                            when(response.getHits())
                                    .thenReturn(
                                            new SearchHits(
                                                    new SearchHit[0], new TotalHits(0, TotalHits.Relation.EQUAL_TO), 0.0f));
                            invocation.<ActionListener<SearchResponse>>getArgument(1).onResponse(response);
                            return null;
                        })
                .when(this.client)
                .search(any(SearchRequest.class), any());

        Exception failure = this.runReconcileCapture(NORMALIZATION_FIELDS);

        assertNotNull("the unlink failure must propagate", failure);
        verify(this.integrationService, never()).deleteIntegrationDocAsync(eq("A"), any());
    }

    /** A NOT_FOUND from Security Analytics on a rule is tolerated, so a re-run converges. */
    @SuppressWarnings("unchecked")
    public void testClearDetection_toleratesSecurityAnalyticsRuleNotFound() {
        this.stubRuleIds(List.of("r1"));
        this.stubList(List.of());
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Object>>getArgument(2).onFailure(notFound());
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .deleteRule(any(), any(), any());

        assertNull("a 404 from Security Analytics must be tolerated", this.runClearDetection());
    }

    /**
     * A NOT_FOUND from Security Analytics on an integration is tolerated; the clear still completes.
     */
    @SuppressWarnings("unchecked")
    public void testReconcileEmptyIntegrations_toleratesSecurityAnalyticsIntegrationNotFound() {
        this.stubList(List.of("A"));
        this.stubEmptyResults(Map.of("A", new IntegrationService.EmptyResult(false, true, true)));
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Object>>getArgument(2).onFailure(notFound());
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .deleteIntegration(any(), any(), any());

        assertNull(this.runReconcileCapture(NORMALIZATION_FIELDS));
        verify(this.integrationService).deleteIntegrationDocAsync(eq("A"), any());
    }
}
