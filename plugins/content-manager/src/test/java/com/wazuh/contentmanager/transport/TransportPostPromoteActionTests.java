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

import org.apache.lucene.search.IndexSearcher;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.action.search.SearchPhaseExecutionException;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.search.SearchResponse;
import org.opensearch.action.search.ShardSearchFailure;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.tasks.Task;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

import com.wazuh.contentmanager.action.MessageStatusResponse;
import com.wazuh.contentmanager.action.PostPromoteRequest;
import com.wazuh.contentmanager.cti.catalog.service.DetectorLookupService.DetectorRules;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/** Unit tests for {@link TransportPostPromoteAction}'s detector guard. */
public class TransportPostPromoteActionTests extends OpenSearchTestCase {

    /** A test to custom promotion carrying one rule, so the detector guard runs. */
    private static final String TEST_TO_CUSTOM_BODY =
            "{\"space\":\"test\",\"changes\":{\"policy\":[],\"integrations\":[],\"kvdbs\":[],"
                    + "\"decoders\":[],\"filters\":[],\"rules\":[{\"operation\":\"add\",\"id\":\"r1\"}]}}";

    /** Runs a test to custom promotion whose detector lookup fails with {@code failure}. */
    @SuppressWarnings("unchecked")
    private MessageStatusResponse promoteWithFailingDetectorLookup(Exception failure) {
        Client client = mock(Client.class);
        doAnswer(
                        invocation -> {
                            ((ActionListener<SearchResponse>) invocation.getArguments()[1]).onFailure(failure);
                            return null;
                        })
                .when(client)
                .search(any(SearchRequest.class), any(ActionListener.class));
        TransportPostPromoteAction action =
                new TransportPostPromoteAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        mock(SpaceService.class),
                        mock(EngineService.class),
                        mock(SecurityAnalyticsService.class),
                        client);

        AtomicReference<MessageStatusResponse> response = new AtomicReference<>();
        action.doExecute(
                mock(Task.class),
                new PostPromoteRequest(TEST_TO_CUSTOM_BODY),
                ActionListener.wrap(response::set, e -> fail(e.getMessage())));
        return response.get();
    }

    /**
     * A guard that could not read the detectors refuses the promotion with the root cause named, not
     * with a bare "Internal Server Error." that needs the Indexer logs to diagnose
     * (wazuh-indexer#1945).
     */
    public void testDetectorLookupFailureNamesTheRootCause() {
        MessageStatusResponse response =
                promoteWithFailingDetectorLookup(
                        new SearchPhaseExecutionException(
                                "query",
                                "all shards failed",
                                new ShardSearchFailure[] {
                                    new ShardSearchFailure(new IndexSearcher.TooManyClauses())
                                }));

        assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.getStatus());
        assertEquals(
                String.format(Locale.ROOT, Constants.E_500_DETECTOR_GUARD_FAILED, "too_many_clauses"),
                response.getMessage());
    }

    /** A permission failure while reading the detectors keeps its own status and message. */
    public void testDetectorLookupSecurityFailureKeepsItsStatus() {
        MessageStatusResponse response =
                promoteWithFailingDetectorLookup(
                        new OpenSearchSecurityException("no permissions", RestStatus.FORBIDDEN));

        assertEquals(RestStatus.FORBIDDEN, response.getStatus());
        assertEquals("no permissions", response.getMessage());
    }

    private static DetectorRules detector(String name, String... ruleIds) {
        return new DetectorRules(name, name, true, List.of(ruleIds));
    }

    /** Nothing would be emptied, so the promotion proceeds. */
    public void testNoRejectionWhenEveryDetectorKeepsARule() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("keeps-one", "a", "b")),
                        Map.of("a", true, "b", true),
                        Map.of("a", false),
                        Set.of());

        assertNull(message);
    }

    /** A single emptied detector keeps the singular wording, naming the rule and the detector. */
    public void testSingleDetectorIsNamedWithItsRule() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("critical", "a")), Map.of("a", true), Map.of("a", false), Set.of());

        assertNotNull(message);
        assertTrue(message, message.contains("detector [critical]"));
        assertTrue(message, message.contains("Rule [a]"));
        assertFalse(message, message.contains("detectors"));
    }

    /**
     * A promotion carrying several rule changes can empty several detectors at once, each through a
     * different rule. All of them must be reported, so the user is not left fixing one per attempt.
     */
    public void testEveryEmptiedDetectorIsReportedWithItsOwnRule() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("config-critical", "a"), detector("audit-critical", "b")),
                        Map.of("a", true, "b", true),
                        Map.of("a", false, "b", false),
                        Set.of());

        assertNotNull(message);
        assertTrue(message, message.contains("2 detectors"));
        assertTrue(message, message.contains("[audit-critical] by disabling rule [b]"));
        assertTrue(message, message.contains("[config-critical] by disabling rule [a]"));
    }

    /** Detectors that survive the promotion are left out of the message. */
    public void testSurvivingDetectorsAreNotReported() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("survives", "a", "b"), detector("emptied", "a")),
                        Map.of("a", true, "b", true),
                        Map.of("a", false),
                        Set.of());

        assertNotNull(message);
        assertTrue(message, message.contains("detector [emptied]"));
        assertFalse(message, message.contains("survives"));
    }

    /**
     * The listing is ordered by detector name, so the same promotion always reports the same text.
     */
    public void testListingIsDeterministic() {
        List<DetectorRules> oneOrder = List.of(detector("zeta", "a"), detector("alpha", "b"));
        List<DetectorRules> otherOrder = List.of(detector("alpha", "b"), detector("zeta", "a"));
        Map<String, Boolean> current = Map.of("a", true, "b", true);
        Map<String, Boolean> incoming = Map.of("a", false, "b", false);

        assertEquals(
                TransportPostPromoteAction.rejectionMessage(oneOrder, current, incoming, Set.of()),
                TransportPostPromoteAction.rejectionMessage(otherOrder, current, incoming, Set.of()));
    }

    /** A removal is reported as the culprit just like a disable. */
    public void testRemovedRuleIsReportedAsTheCulprit() {
        String message =
                TransportPostPromoteAction.rejectionMessage(
                        List.of(detector("critical", "a")), Map.of("a", true), Map.of(), Set.of("a"));

        assertNotNull(message);
        assertTrue(message, message.contains("Rule [a]"));
        assertTrue(message, message.contains("detector [critical]"));
    }

    // ── Policy id validation (wazuh-indexer#2006) ────────────────────────────

    /** The marker failure the stubbed payload build raises once the gathering phase passed. */
    private static final String REACHED_PAYLOAD_BUILD = "reached the payload build";

    /** A draft to test promotion whose only change is the policy update with the given id. */
    private static String draftPolicyUpdateBody(String policyId) {
        return "{\"space\":\"draft\",\"changes\":{\"policy\":[{\"operation\":\"update\",\"id\":\""
                + policyId
                + "\"}],\"integrations\":[],\"kvdbs\":[],\"decoders\":[],\"filters\":[],\"rules\":[]}}";
    }

    /**
     * Runs a draft to test promotion against a space service whose draft policy has {@code
     * document.id} "policy-doc-id". The payload build is stubbed to fail with {@link
     * #REACHED_PAYLOAD_BUILD}, so the response tells whether the gathering phase let the policy
     * update through.
     */
    @SuppressWarnings("unchecked")
    private MessageStatusResponse promotePolicyUpdate(String requestedPolicyId) {
        SpaceService spaceService = mock(SpaceService.class);
        when(spaceService.getIndexForResourceType(anyString())).thenCallRealMethod();
        doAnswer(
                        invocation -> {
                            ((ActionListener<Map<String, Object>>) invocation.getArguments()[1])
                                    .onResponse(
                                            Map.of(
                                                    Constants.KEY_DOCUMENT,
                                                    Map.of(Constants.KEY_ID, "policy-doc-id"),
                                                    Constants.KEY_SPACE,
                                                    Map.of(Constants.KEY_NAME, "draft")));
                            return null;
                        })
                .when(spaceService)
                .getPolicy(anyString(), any(ActionListener.class));
        doAnswer(
                        invocation -> {
                            ((ActionListener<?>) invocation.getArguments()[10])
                                    .onFailure(new IllegalArgumentException(REACHED_PAYLOAD_BUILD));
                            return null;
                        })
                .when(spaceService)
                .buildEnginePayload(
                        any(), anyString(), any(), any(), any(), any(), any(), any(), any(), any(), any());

        TransportPostPromoteAction action =
                new TransportPostPromoteAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        spaceService,
                        mock(EngineService.class),
                        mock(SecurityAnalyticsService.class),
                        mock(Client.class));

        AtomicReference<MessageStatusResponse> response = new AtomicReference<>();
        action.doExecute(
                mock(Task.class),
                new PostPromoteRequest(draftPolicyUpdateBody(requestedPolicyId)),
                ActionListener.wrap(response::set, e -> fail(e.getMessage())));
        return response.get();
    }

    /**
     * A policy update whose id is not the space policy's document.id is rejected with a 400 naming
     * the expected id, before anything is written. It used to be accepted and indexed as a second
     * policy document for the target space, which the managers' engine content sync then rejected on
     * every cycle (wazuh-indexer#2006).
     */
    public void testPolicyUpdateWithUnknownIdIsRejected() {
        MessageStatusResponse response = promotePolicyUpdate("not-the-policy-id");

        assertEquals(RestStatus.BAD_REQUEST, response.getStatus());
        assertEquals(
                String.format(
                        Locale.ROOT,
                        Constants.E_400_POLICY_ID_MISMATCH,
                        "not-the-policy-id",
                        "draft",
                        "policy-doc-id"),
                response.getMessage());
    }

    /** A policy update carrying the space policy's document.id passes the gathering phase. */
    public void testPolicyUpdateWithMatchingIdIsAccepted() {
        MessageStatusResponse response = promotePolicyUpdate("policy-doc-id");

        assertEquals(REACHED_PAYLOAD_BUILD, response.getMessage());
    }
}
