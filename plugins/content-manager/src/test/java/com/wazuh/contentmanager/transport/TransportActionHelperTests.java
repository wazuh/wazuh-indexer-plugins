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

import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.model.Space;
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
    private ObjectNode payload;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.spaceService = mock(SpaceService.class);
        this.engine = mock(EngineService.class);
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
                this.engine, this.spaceService, Set.of(Space.STANDARD.toString()));

        verify(this.engine).promoteAsync(eq(this.payload), any(ActionListener.class));
    }

    public void testSkipsReloadWhenStandardSpaceUnchanged() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine, this.spaceService, Set.of(Space.DRAFT.toString()));

        verifyNoInteractions(this.spaceService);
        verifyNoInteractions(this.engine);
    }

    public void testSkipsReloadWhenNoSpaceChanged() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(this.engine, this.spaceService, Set.of());

        verifyNoInteractions(this.spaceService);
        verifyNoInteractions(this.engine);
    }

    public void testSkipsReloadWhenChangedSpacesIsNull() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(this.engine, this.spaceService, null);

        verifyNoInteractions(this.spaceService);
        verifyNoInteractions(this.engine);
    }

    /** A missing Engine must not build a payload, and must not fail the completed mutation. */
    public void testToleratesMissingEngine() {
        TransportActionHelper.reloadStandardSpaceIntoEngine(
                null, this.spaceService, Set.of(Space.STANDARD.toString()));

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
                this.engine, this.spaceService, Set.of(Space.STANDARD.toString()));

        verify(this.engine).promoteAsync(eq(this.payload), any(ActionListener.class));
    }

    public void testTolerantOfEngineFailure() {
        stubPayloadBuild();
        stubPromoteAsyncFailure(new RuntimeException("socket unavailable"));

        TransportActionHelper.reloadStandardSpaceIntoEngine(
                this.engine, this.spaceService, Set.of(Space.STANDARD.toString()));

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
                this.engine, this.spaceService, Set.of(Space.STANDARD.toString()));

        verify(this.engine, never()).promoteAsync(any(JsonNode.class), any(ActionListener.class));
    }
}
