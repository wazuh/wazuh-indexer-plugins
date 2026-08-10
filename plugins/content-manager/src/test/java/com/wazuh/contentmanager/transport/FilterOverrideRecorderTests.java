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

import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;

import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/** Unit tests for {@link FilterOverrideRecorder}. */
public class FilterOverrideRecorderTests extends OpenSearchTestCase {

    private UserOverridesService overridesService;
    private AtomicInteger onDoneCalls;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.overridesService = mock(UserOverridesService.class);
        this.onDoneCalls = new AtomicInteger();
    }

    /** Makes the registry write succeed. */
    private void stubRegistrySucceeding() {
        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Void>>getArgument(2).onResponse(null);
                            return null;
                        })
                .when(this.overridesService)
                .update(any(), any(), any());
    }

    private void record(String spaceName) {
        FilterOverrideRecorder.record(
                this.overridesService,
                spaceName,
                UserOverridesService.storeFilter("f1", "{}"),
                "f1",
                this.onDoneCalls::incrementAndGet);
    }

    /** A filter in the standard space is recorded, and the request is answered afterwards. */
    public void testStandardSpaceIsRecorded() {
        stubRegistrySucceeding();

        record(Space.STANDARD.toString());

        verify(this.overridesService).update(any(), any(), any());
        assertEquals("the request must be answered", 1, this.onDoneCalls.get());
    }

    /**
     * Every other space is skipped outright.
     *
     * <p>This is the guard that keeps a filter created in {@code draft} out of the standard registry.
     * Without it, the next synchronization would recreate that filter in {@code standard} -- handing
     * the user a resource in a space they never put it in.
     */
    public void testOtherSpacesAreNotRecorded() {
        for (String space :
                new String[] {Space.DRAFT.toString(), Space.TEST.toString(), Space.CUSTOM.toString()}) {
            this.overridesService = mock(UserOverridesService.class);
            this.onDoneCalls = new AtomicInteger();

            record(space);

            verifyNoInteractions(this.overridesService);
            assertEquals(
                    "the request must still be answered for space " + space, 1, this.onDoneCalls.get());
        }
    }

    /**
     * A registry failure must not fail the request. By the time this runs the filter has already been
     * written and the space hash recalculated, so the user's request did succeed.
     */
    public void testTheRequestIsAnsweredWhenTheRegistryFails() {
        doAnswer(
                        invocation -> {
                            invocation
                                    .<ActionListener<Void>>getArgument(2)
                                    .onFailure(new java.io.IOException("registry unavailable"));
                            return null;
                        })
                .when(this.overridesService)
                .update(any(), any(), any());

        record(Space.STANDARD.toString());

        assertEquals("a registry failure must not swallow the response", 1, this.onDoneCalls.get());
    }

    /** The response is sent exactly once, never twice. */
    public void testTheRequestIsAnsweredExactlyOnce() {
        stubRegistrySucceeding();

        record(Space.STANDARD.toString());

        assertEquals(1, this.onDoneCalls.get());
    }

    /**
     * The mutator handed to the registry is the one the caller passed, applied to the stored state.
     */
    public void testTheCallersMutatorIsTheOneApplied() {
        stubRegistrySucceeding();
        org.mockito.ArgumentCaptor<java.util.function.UnaryOperator<UserOverrides>> captor =
                org.mockito.ArgumentCaptor.forClass(java.util.function.UnaryOperator.class);

        FilterOverrideRecorder.record(
                this.overridesService,
                Space.STANDARD.toString(),
                UserOverridesService.removeFilter("f1"),
                "f1",
                this.onDoneCalls::incrementAndGet);

        verify(this.overridesService).update(any(), captor.capture(), any());

        UserOverrides current =
                new UserOverrides(
                        null, new ArrayList<>(java.util.List.of(new UserOverrides.StoredFilter("f1", "{}"))));
        assertTrue(
                "the recorder must not substitute the caller's mutator",
                captor.getValue().apply(current).getFilters().isEmpty());
    }
}
