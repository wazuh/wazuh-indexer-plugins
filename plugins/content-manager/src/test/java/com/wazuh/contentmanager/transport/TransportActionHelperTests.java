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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.OpenSearchSecurityException;
import org.opensearch.OpenSearchStatusException;
import org.opensearch.cluster.block.ClusterBlockException;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Unit tests for {@link TransportActionHelper#reloadStandardSpaceIntoEngine}, the hook that keeps
 * the Engine's copy of the standard policy in sync after a content mutation. Without it the Engine
 * serves the snapshot from its last full load, so changes such as toggling an integration's {@code
 * enabled} flag never reach the log test endpoint.
 */
public class TransportActionHelperTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SpaceService spaceService;
    private EngineService engine;
    private EngineContentLoader engineContentLoader;
    private Client client;
    private ObjectNode payload;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.spaceService = mock(SpaceService.class);
        this.engine = mock(EngineService.class);
        this.engineContentLoader = mock(EngineContentLoader.class);
        this.client = mock(Client.class);
        this.payload = MAPPER.createObjectNode();
        this.payload.put("space", Space.STANDARD.toString());
    }

    /** Stubs {@link SpaceService#buildEnginePayload} to hand {@link #payload} to its listener. */
    @SuppressWarnings("unchecked")
    private void stubPayloadBuild() {
        doAnswer(
                        invocation -> {
                            ActionListener<JsonNode> listener =
                                    (ActionListener<JsonNode>) invocation.getArguments()[1];
                            listener.onResponse(this.payload);
                            return null;
                        })
                .when(this.spaceService)
                .buildEnginePayload(eq(Space.STANDARD.toString()), any(ActionListener.class));
    }

    /** Stubs {@link EngineService#promoteAsync} to invoke its listener with the given response. */
    @SuppressWarnings("unchecked")
    private void stubPromoteAsync(RestResponse response) {
        doAnswer(
                        invocation -> {
                            ActionListener<RestResponse> listener =
                                    (ActionListener<RestResponse>) invocation.getArguments()[1];
                            listener.onResponse(response);
                            return null;
                        })
                .when(this.engine)
                .promoteAsync(any(JsonNode.class), any(ActionListener.class));
    }

    /** Stubs {@link EngineService#promoteAsync} to invoke its listener with a failure. */
    @SuppressWarnings("unchecked")
    private void stubPromoteAsyncFailure(Exception exception) {
        doAnswer(
                        invocation -> {
                            ActionListener<RestResponse> listener =
                                    (ActionListener<RestResponse>) invocation.getArguments()[1];
                            listener.onFailure(exception);
                            return null;
                        })
                .when(this.engine)
                .promoteAsync(any(JsonNode.class), any(ActionListener.class));
    }

    public void testPromotesStandardSpaceWhenItsHashChanged() {
        stubPayloadBuild();
        stubPromoteAsync(new RestResponse("OK", RestStatus.OK.getStatus()));

        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine,
                this.spaceService,
                Set.of(Space.STANDARD.toString()),
                this.engineContentLoader,
                this.client);

        verify(this.engine).promoteAsync(eq(this.payload), any(ActionListener.class));
    }

    public void testSkipsReloadWhenStandardSpaceUnchanged() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine,
                this.spaceService,
                Set.of(Space.DRAFT.toString()),
                this.engineContentLoader,
                this.client);

        verifyNoInteractions(this.spaceService);
        verifyNoInteractions(this.engine);
    }

    public void testSkipsReloadWhenNoSpaceChanged() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine, this.spaceService, Set.of(), this.engineContentLoader, this.client);

        verifyNoInteractions(this.spaceService);
        verifyNoInteractions(this.engine);
    }

    public void testSkipsReloadWhenChangedSpacesIsNull() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine, this.spaceService, null, this.engineContentLoader, this.client);

        verifyNoInteractions(this.spaceService);
        verifyNoInteractions(this.engine);
    }

    /** A missing Engine must not build a payload, and must not fail the completed mutation. */
    public void testToleratesMissingEngine() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(
                null,
                this.spaceService,
                Set.of(Space.STANDARD.toString()),
                this.engineContentLoader,
                this.client);

        verifyNoInteractions(this.spaceService);
    }

    /**
     * The mutation is already persisted by the time the reload runs, so an Engine that rejects or
     * cannot be reached is logged, never rethrown.
     */
    public void testTolerantOfEngineRejection() {
        stubPayloadBuild();
        stubPromoteAsync(new RestResponse("rejected", RestStatus.INTERNAL_SERVER_ERROR.getStatus()));

        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine,
                this.spaceService,
                Set.of(Space.STANDARD.toString()),
                this.engineContentLoader,
                this.client);

        verify(this.engine).promoteAsync(eq(this.payload), any(ActionListener.class));
    }

    public void testTolerantOfEngineFailure() {
        stubPayloadBuild();
        stubPromoteAsyncFailure(new RuntimeException("socket unavailable"));

        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine,
                this.spaceService,
                Set.of(Space.STANDARD.toString()),
                this.engineContentLoader,
                this.client);

        verify(this.engine).promoteAsync(eq(this.payload), any(ActionListener.class));
    }

    /** A payload build failure is logged, and never reaches the Engine. */
    @SuppressWarnings("unchecked")
    public void testTolerantOfPayloadBuildFailure() {
        doAnswer(
                        invocation -> {
                            ActionListener<JsonNode> listener =
                                    (ActionListener<JsonNode>) invocation.getArguments()[1];
                            listener.onFailure(new RuntimeException("standard policy missing"));
                            return null;
                        })
                .when(this.spaceService)
                .buildEnginePayload(eq(Space.STANDARD.toString()), any(ActionListener.class));

        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine,
                this.spaceService,
                Set.of(Space.STANDARD.toString()),
                this.engineContentLoader,
                this.client);

        verify(this.engine, never()).promoteAsync(any(JsonNode.class), any(ActionListener.class));
    }

    public void testClassifyExceptionReturnsSecurityExceptionStatus() {
        OpenSearchSecurityException securityException =
                new OpenSearchSecurityException("not authorized", RestStatus.FORBIDDEN);

        RestResponse classified = TransportActionHelper.classifyException(securityException);

        assertNotNull(classified);
        assertEquals(RestStatus.FORBIDDEN.getStatus(), classified.getStatus());
    }

    /**
     * A cluster block's own {@code status()} often resolves below 500 (e.g. 403 for a write block),
     * but by convention it is a server fault, so it must be left unclassified rather than passed
     * through as a client error.
     */
    public void testClassifyExceptionLeavesClusterBlockUnclassified() {
        ClusterBlockException clusterBlockException =
                new ClusterBlockException(Map.of("my-index", Set.of(IndexMetadata.INDEX_WRITE_BLOCK)));
        assertEquals(RestStatus.FORBIDDEN, clusterBlockException.status());

        RestResponse classified = TransportActionHelper.classifyException(clusterBlockException);

        assertNull(classified);
    }

    public void testClassifyExceptionReturnsOpenSearchExceptionStatusBelow500() {
        OpenSearchStatusException conflict =
                new OpenSearchStatusException(
                        "resource already exists in target space", RestStatus.CONFLICT);

        RestResponse classified = TransportActionHelper.classifyException(conflict);

        assertNotNull(classified);
        assertEquals(RestStatus.CONFLICT.getStatus(), classified.getStatus());
    }

    public void testClassifyExceptionLeavesServerFaultOpenSearchExceptionUnclassified() {
        OpenSearchStatusException serverFault =
                new OpenSearchStatusException("downstream unavailable", RestStatus.INTERNAL_SERVER_ERROR);

        RestResponse classified = TransportActionHelper.classifyException(serverFault);

        assertNull(classified);
    }

    public void testClassifyExceptionReturnsBadRequestForIllegalArgument() {
        RestResponse classified =
                TransportActionHelper.classifyException(new IllegalArgumentException("invalid input"));

        assertNotNull(classified);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), classified.getStatus());
    }

    public void testClassifyExceptionReturnsNullForUnclassifiedException() {
        RestResponse classified =
                TransportActionHelper.classifyException(new RuntimeException("unexpected"));

        assertNull(classified);
    }
}
