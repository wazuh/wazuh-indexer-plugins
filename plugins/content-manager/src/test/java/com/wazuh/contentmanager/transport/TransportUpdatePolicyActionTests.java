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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.function.UnaryOperator;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.UpdatePolicyRequest;
import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link TransportUpdatePolicyAction}'s {@code metadata.date}/{@code
 * metadata.modified} handling: unlike the shared {@code Resource.setCreationTime}/{@code
 * setLastModificationTime} helpers used by other resource types, policy updates merge these fields
 * inline against the existing document rather than through that shared code path.
 */
public class TransportUpdatePolicyActionTests extends OpenSearchTestCase {

    private static final String EXISTING_CREATION_DATE = "2020-01-01T00:00:00.000Z";
    private static final ObjectMapper MAPPER = new ObjectMapper();

    private Client client;
    private SpaceService spaceService;
    private UserOverridesService overridesService;
    private TransportUpdatePolicyAction action;
    private IndexResponse indexResponse;

    @SuppressWarnings("unchecked")
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(Settings.EMPTY);

        this.client = mock(Client.class);
        this.spaceService = mock(SpaceService.class);
        this.overridesService = mock(UserOverridesService.class);
        EngineService engineService = mock(EngineService.class);
        this.indexResponse = mock(IndexResponse.class);

        this.action =
                new TransportUpdatePolicyAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        this.spaceService,
                        engineService,
                        mock(EngineContentLoader.class),
                        this.client,
                        this.overridesService);

        // Recording an override succeeds by default, so the tests that predate the registry are
        // unaffected by it.
        doAnswer(
                        invocation -> {
                            ActionListener<Void> l = invocation.getArgument(2);
                            l.onResponse(null);
                            return null;
                        })
                .when(this.overridesService)
                .update(any(), any(), any(ActionListener.class));

        when(this.spaceService.getKnownEnrichmentTypes()).thenReturn(Collections.emptySet());
        when(this.indexResponse.getId()).thenReturn("draft-doc-id");

        doAnswer(
                        invocation -> {
                            ActionListener<String> l = invocation.getArgument(3);
                            l.onResponse("draft-doc-id");
                            return null;
                        })
                .when(this.spaceService)
                .findDocumentIdAsync(any(), any(), any(), any(ActionListener.class));

        doAnswer(
                        invocation -> {
                            ActionListener<IndexResponse> l = invocation.getArgument(1);
                            l.onResponse(this.indexResponse);
                            return null;
                        })
                .when(this.client)
                .index(any(IndexRequest.class), any(ActionListener.class));

        doAnswer(
                        invocation -> {
                            ActionListener<Set<String>> l = invocation.getArgument(1);
                            l.onResponse(Collections.emptySet());
                            return null;
                        })
                .when(this.spaceService)
                .calculateAndUpdate(any(), any(ActionListener.class));
    }

    @After
    public void tearDown() throws Exception {
        clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    /** Builds the {@code getPolicy()} return value: a draft policy with a known creation date. */
    private Map<String, Object> currentDraftPolicy() {
        Map<String, Object> metadata = new HashMap<>();
        metadata.put(Constants.KEY_DATE, EXISTING_CREATION_DATE);
        metadata.put(Constants.KEY_TITLE, "Existing policy");
        metadata.put(Constants.KEY_AUTHOR, "Wazuh Inc.");
        metadata.put(Constants.KEY_DESCRIPTION, "Existing description");
        metadata.put(Constants.KEY_DOCUMENTATION, "");
        metadata.put(Constants.KEY_REFERENCES, Collections.emptyList());

        Map<String, Object> document = new HashMap<>();
        document.put(Constants.KEY_ID, "policy-doc-id");
        document.put(Constants.KEY_METADATA, metadata);
        document.put(Constants.KEY_INTEGRATIONS, Collections.emptyList());
        document.put(Constants.KEY_FILTERS, Collections.emptyList());

        Map<String, Object> policy = new HashMap<>();
        policy.put(Constants.KEY_DOCUMENT, document);
        return policy;
    }

    private String draftUpdateBody(String modifiedField) {
        String modifiedLine = modifiedField == null ? "" : "\"modified\": \"" + modifiedField + "\",";
        return "{"
                + "\"type\": \"policy\","
                + "\"resource\": {"
                + "\"root_decoder\": \"\","
                + "\"integrations\": [],"
                + "\"filters\": [],"
                + "\"enrichments\": [],"
                + "\"enabled\": true,"
                + "\"index_unclassified_events\": false,"
                + "\"index_discarded_events\": false,"
                + "\"metadata\": {"
                + "\"title\": \"Updated policy\","
                + modifiedLine
                + "\"author\": \"Test\","
                + "\"description\": \"Updated description\","
                + "\"documentation\": \"\","
                + "\"references\": []"
                + "}"
                + "}"
                + "}";
    }

    /** Captures the {@code document.metadata} node actually sent to the indexing client. */
    private JsonNode capturedIndexedMetadata() throws Exception {
        ArgumentCaptor<IndexRequest> captor = ArgumentCaptor.forClass(IndexRequest.class);
        verify(this.client).index(captor.capture(), any(ActionListener.class));
        JsonNode source = MAPPER.readTree(captor.getValue().source().utf8ToString());
        return source.path(Constants.KEY_DOCUMENT).path(Constants.KEY_METADATA);
    }

    public void testUpdatePolicy_honorsCallerSuppliedModified() throws Exception {
        doAnswer(
                        invocation -> {
                            ActionListener<Map<String, Object>> l = invocation.getArgument(1);
                            l.onResponse(currentDraftPolicy());
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(any(), any(ActionListener.class));

        String callerModified = "2021-05-05T00:00:00.000Z";
        UpdatePolicyRequest request = new UpdatePolicyRequest("draft", draftUpdateBody(callerModified));

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    return true;
                                }));

        JsonNode metadata = capturedIndexedMetadata();
        Assert.assertEquals(
                "Caller-supplied 'modified' should be honored",
                callerModified,
                metadata.path(Constants.KEY_MODIFIED).asText());
        Assert.assertEquals(
                "'date' should always be preserved from the existing document, never the request body",
                EXISTING_CREATION_DATE,
                metadata.path(Constants.KEY_DATE).asText());
    }

    public void testUpdatePolicy_generatesModifiedWhenAbsent() throws Exception {
        doAnswer(
                        invocation -> {
                            ActionListener<Map<String, Object>> l = invocation.getArgument(1);
                            l.onResponse(currentDraftPolicy());
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(any(), any(ActionListener.class));

        UpdatePolicyRequest request = new UpdatePolicyRequest("draft", draftUpdateBody(null));

        @SuppressWarnings("unchecked")
        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(mock(Task.class), request, listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    return true;
                                }));

        JsonNode metadata = capturedIndexedMetadata();
        Assert.assertFalse(
                "'modified' should be generated when absent from the request",
                metadata.path(Constants.KEY_MODIFIED).asText("").isBlank());
        Assert.assertEquals(
                "'date' should always be preserved from the existing document",
                EXISTING_CREATION_DATE,
                metadata.path(Constants.KEY_DATE).asText());
    }

    // --- User overrides registry -------------------------------------------------------------

    private static final List<String> CTI_ENRICHMENTS =
            List.of(
                    "geo", "connection", "url_full", "url_domain", "hash_md5", "hash_sha1", "hash_sha256");

    /** Stubs {@code getPolicy()} with a standard policy holding the given enrichments. */
    @SuppressWarnings("unchecked")
    private void stubStandardPolicy(List<String> storedEnrichments) {
        Map<String, Object> policy = currentDraftPolicy();
        Map<String, Object> document = (Map<String, Object>) policy.get(Constants.KEY_DOCUMENT);
        document.put(Constants.KEY_ENRICHMENTS, storedEnrichments);

        // Any enrichment absent from this set is rejected with 400 before the merge runs.
        when(this.spaceService.getKnownEnrichmentTypes()).thenReturn(Set.copyOf(CTI_ENRICHMENTS));

        doAnswer(
                        invocation -> {
                            ActionListener<Map<String, Object>> l = invocation.getArgument(1);
                            l.onResponse(policy);
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(any(), any(ActionListener.class));
    }

    /** A standard-space update body carrying exactly the given enrichments. */
    private static String standardUpdateBody(List<String> enrichments) {
        String quoted =
                enrichments.stream().map(e -> "\"" + e + "\"").reduce((a, b) -> a + ", " + b).orElse("");
        return "{"
                + "\"type\": \"policy\","
                + "\"resource\": {"
                + "\"root_decoder\": \"\","
                + "\"integrations\": [],"
                + "\"filters\": [],"
                + "\"enrichments\": ["
                + quoted
                + "],"
                + "\"enabled\": true,"
                + "\"index_unclassified_events\": true,"
                + "\"index_discarded_events\": false,"
                + "\"metadata\": {"
                + "\"title\": \"Existing policy\","
                + "\"author\": \"Wazuh Inc.\","
                + "\"description\": \"Existing description\","
                + "\"documentation\": \"\","
                + "\"references\": []"
                + "}"
                + "}"
                + "}";
    }

    /** Runs a standard-space update and returns the mutator handed to the registry. */
    @SuppressWarnings("unchecked")
    private UnaryOperator<UserOverrides> captureRecordedMutator(List<String> incomingEnrichments) {
        this.action.doExecute(
                mock(Task.class),
                new UpdatePolicyRequest("standard", standardUpdateBody(incomingEnrichments)),
                mock(ActionListener.class));

        ArgumentCaptor<UnaryOperator<UserOverrides>> captor =
                ArgumentCaptor.forClass(UnaryOperator.class);
        verify(this.overridesService).update(any(), captor.capture(), any(ActionListener.class));
        return captor.getValue();
    }

    /**
     * Saving the standard policy records all four settings, and the enrichment change is stored as a
     * delta so enrichments CTI publishes later still reach this user.
     */
    public void testStandardUpdateRecordsAllFourSettingsAndAnEnrichmentDelta() {
        stubStandardPolicy(CTI_ENRICHMENTS);

        // The client sends six of the seven, dropping "geo".
        List<String> incoming =
                List.of("connection", "url_full", "url_domain", "hash_md5", "hash_sha1", "hash_sha256");
        UserOverrides recorded =
                captureRecordedMutator(incoming)
                        .apply(new UserOverrides(null, new java.util.ArrayList<>()));

        Assert.assertEquals(Boolean.TRUE, recorded.getPolicy().getEnabled());
        Assert.assertEquals(Boolean.TRUE, recorded.getPolicy().getIndexUnclassifiedEvents());
        Assert.assertEquals(Boolean.FALSE, recorded.getPolicy().getIndexDiscardedEvents());
        Assert.assertEquals(Set.of("geo"), recorded.getPolicy().getEnrichments().getRemoved());
        Assert.assertTrue(recorded.getPolicy().getEnrichments().getAdded().isEmpty());
    }

    /**
     * Re-adding an enrichment the user had previously removed clears the removal, so the same value
     * does not stay suppressed forever.
     */
    public void testReAddingAPreviouslyRemovedEnrichmentClearsTheRemoval() {
        // The stored policy is the result of the first save: six enrichments, no "geo".
        List<String> withoutGeo =
                List.of("connection", "url_full", "url_domain", "hash_md5", "hash_sha1", "hash_sha256");
        stubStandardPolicy(withoutGeo);

        UserOverrides priorState =
                new UserOverrides(
                        new UserOverrides.PolicySettings(
                                Boolean.TRUE,
                                Boolean.TRUE,
                                Boolean.FALSE,
                                new UserOverrides.EnrichmentDelta(Set.of("geo"), Set.of())),
                        new java.util.ArrayList<>());

        // The user re-checks "geo": the body carries all seven again.
        UserOverrides recorded = captureRecordedMutator(CTI_ENRICHMENTS).apply(priorState);

        Assert.assertTrue(
                "the removal must be cleared",
                recorded.getPolicy().getEnrichments().getRemoved().isEmpty());
        Assert.assertEquals(Set.of("geo"), recorded.getPolicy().getEnrichments().getAdded());
    }

    /** The filters already stored in the registry survive a policy save untouched. */
    public void testRecordingPolicySettingsKeepsTheStoredFilters() {
        stubStandardPolicy(CTI_ENRICHMENTS);

        UserOverrides priorState =
                new UserOverrides(
                        null,
                        new java.util.ArrayList<>(
                                List.of(new UserOverrides.StoredFilter("f1", "{\"document\":{}}"))));

        UserOverrides recorded = captureRecordedMutator(CTI_ENRICHMENTS).apply(priorState);

        Assert.assertEquals(1, recorded.getFilters().size());
        Assert.assertEquals("f1", recorded.getFilters().get(0).getId());
    }

    /** A draft-space update records nothing: draft is never rebuilt from CTI. */
    @SuppressWarnings("unchecked")
    public void testDraftUpdateDoesNotTouchTheRegistry() {
        doAnswer(
                        invocation -> {
                            ActionListener<Map<String, Object>> l = invocation.getArgument(1);
                            l.onResponse(currentDraftPolicy());
                            return null;
                        })
                .when(this.spaceService)
                .getPolicy(any(), any(ActionListener.class));

        this.action.doExecute(
                mock(Task.class),
                new UpdatePolicyRequest("draft", draftUpdateBody(null)),
                mock(ActionListener.class));

        verify(this.overridesService, never()).update(any(), any(), any(ActionListener.class));
    }

    /**
     * A registry write failure must not fail the user's update: the policy has already been indexed,
     * so the request succeeded. The failure is logged and the response stays OK.
     */
    @SuppressWarnings("unchecked")
    public void testUpdateStillSucceedsWhenRecordingFails() {
        stubStandardPolicy(CTI_ENRICHMENTS);
        doAnswer(
                        invocation -> {
                            ActionListener<Void> l = invocation.getArgument(2);
                            l.onFailure(new RuntimeException("registry unavailable"));
                            return null;
                        })
                .when(this.overridesService)
                .update(any(), any(), any(ActionListener.class));

        ActionListener<MessageStatusResponse> listener = mock(ActionListener.class);
        this.action.doExecute(
                mock(Task.class),
                new UpdatePolicyRequest("standard", standardUpdateBody(CTI_ENRICHMENTS)),
                listener);

        verify(listener)
                .onResponse(
                        argThat(
                                response -> {
                                    Assert.assertEquals(RestStatus.OK, response.getStatus());
                                    return true;
                                }));
    }
}
