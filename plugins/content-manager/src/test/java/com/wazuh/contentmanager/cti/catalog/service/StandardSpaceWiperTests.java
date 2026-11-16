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
package com.wazuh.contentmanager.cti.catalog.service;

import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** Tests for the wiper the ruleset consumer gives the snapshot service. */
public class StandardSpaceWiperTests extends OpenSearchTestCase {

    private static final String CONSUMER = "cti:catalog:consumer:ruleset";

    @Mock private SecurityAnalyticsService securityAnalyticsService;
    @Mock private SpaceService spaceService;

    private AutoCloseable closeable;

    /** The order in which the two deletions were asked for. */
    private final List<String> calls = new ArrayList<>();

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        this.closeable.close();
    }

    /** Answers the Security Analytics deletion, recording the call. */
    private void securityAnalyticsSucceeds() {
        doAnswer(
                        invocation -> {
                            this.calls.add("security-analytics");
                            invocation.<ActionListener<Object>>getArgument(1).onResponse(null);
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .deleteSpaceResources(any(Space.class), any());
    }

    /** Answers the content deletion, recording the call. */
    private void contentSucceeds() {
        doAnswer(
                        invocation -> {
                            this.calls.add("content");
                            invocation.<ActionListener<Void>>getArgument(1).onResponse(null);
                            return null;
                        })
                .when(this.spaceService)
                .deleteSpaceResources(any(Space.class), any());
    }

    /**
     * The wipe deletes the Standard space on both sides, Security Analytics first: the detectors and
     * rules there are built from the content, so they go before the content they were built from.
     */
    public void testWipeDeletesTheStandardSpaceOnBothSides() {
        this.securityAnalyticsSucceeds();
        this.contentSucceeds();

        boolean wiped =
                new StandardSpaceWiper(this.securityAnalyticsService, this.spaceService, CONSUMER).wipe();

        assertTrue("a wipe that completes reports success", wiped);
        assertEquals(List.of("security-analytics", "content"), this.calls);

        ArgumentCaptor<Space> securityAnalyticsSpace = ArgumentCaptor.forClass(Space.class);
        verify(this.securityAnalyticsService)
                .deleteSpaceResources(securityAnalyticsSpace.capture(), any());
        assertEquals(Space.STANDARD, securityAnalyticsSpace.getValue());

        ArgumentCaptor<Space> contentSpace = ArgumentCaptor.forClass(Space.class);
        verify(this.spaceService).deleteSpaceResources(contentSpace.capture(), any());
        assertEquals(Space.STANDARD, contentSpace.getValue());
    }

    /**
     * A Security Analytics failure stops the wipe, and the content is not deleted either: half a wipe
     * is worse than none, because the snapshot would then load over what is left.
     */
    public void testWipeFailsAndStopsWhenSecurityAnalyticsFails() {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Object>>getArgument(1)
                                    .onFailure(new IOException("security analytics is unavailable"));
                            return null;
                        })
                .when(this.securityAnalyticsService)
                .deleteSpaceResources(any(Space.class), any());

        boolean wiped =
                new StandardSpaceWiper(this.securityAnalyticsService, this.spaceService, CONSUMER).wipe();

        assertFalse("a wipe that fails reports failure", wiped);
        verify(this.spaceService, never()).deleteSpaceResources(any(Space.class), any());
    }

    /**
     * A failure deleting the content documents fails the wipe too, and this is the case where the two
     * steps are not a transaction: Security Analytics has already been emptied by then. What the
     * caller gets is still the guarantee it needs -- the content documents were not confirmed gone,
     * so the snapshot is not written on top of them -- and the phases recorded before the load push
     * the Security Analytics side again on the next synchronization.
     */
    /** A failure deleting the content documents fails the wipe too. */
    public void testWipeFailsWhenTheContentDeletionFails() {
        this.securityAnalyticsSucceeds();
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Void>>getArgument(1)
                                    .onFailure(new IOException("bulk deletion failed"));
                            return null;
                        })
                .when(this.spaceService)
                .deleteSpaceResources(any(Space.class), any());

        boolean wiped =
                new StandardSpaceWiper(this.securityAnalyticsService, this.spaceService, CONSUMER).wipe();

        assertFalse("a wipe that fails reports failure", wiped);
        verify(this.securityAnalyticsService).deleteSpaceResources(eq(Space.STANDARD), any());
    }
}
