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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.model.UserOverrides;
import com.wazuh.contentmanager.cti.catalog.service.EngineContentLoader;
import com.wazuh.contentmanager.cti.catalog.service.UserOverridesService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import org.mockito.ArgumentCaptor;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/**
 * Unit tests for {@link TransportUpdateIntegrationAction}'s registry bookkeeping.
 *
 * <p>The hook is exercised directly. Everything upstream of it -- validation, the standard-space
 * field restore, the detector sync -- is the action's pre-existing behaviour and unaffected here.
 */
public class TransportUpdateIntegrationActionTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private UserOverridesService overridesService;
    private TransportUpdateIntegrationAction action;
    private AtomicInteger onDoneCalls;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(
                Settings.builder().put("plugins.content_manager.engine.mock", true).build());

        this.overridesService = mock(UserOverridesService.class);
        this.onDoneCalls = new AtomicInteger();
        this.action =
                new TransportUpdateIntegrationAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        mock(Client.class),
                        mock(EngineService.class),
                        mock(EngineContentLoader.class),
                        this.overridesService);

        doAnswer(
                        invocation -> {
                            invocation.<ActionListener<Void>>getArgument(2).onResponse(null);
                            return null;
                        })
                .when(this.overridesService)
                .update(any(), any(), any());
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

    /** The document as it was indexed: the integration under a {@code document} key. */
    private static ObjectNode indexedWrapper(String id, boolean enabled) {
        ObjectNode document = MAPPER.createObjectNode();
        document.put("id", id);
        document.put("enabled", enabled);
        ObjectNode wrapper = MAPPER.createObjectNode();
        wrapper.set("document", document);
        return wrapper;
    }

    /** Runs the hook and returns the mutator handed to the registry. */
    private UserOverrides recordAndApply(String spaceName, String id, boolean enabled) {
        this.action.afterResourceCommitted(
                id, spaceName, indexedWrapper(id, enabled), this.onDoneCalls::incrementAndGet);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<UnaryOperator<UserOverrides>> captor =
                ArgumentCaptor.forClass(UnaryOperator.class);
        verify(this.overridesService).update(any(), captor.capture(), any());

        return captor.getValue().apply(new UserOverrides(null, new ArrayList<>(), new ArrayList<>()));
    }

    /** Disabling an integration in the standard space records the choice under its id. */
    public void testDisablingAStandardIntegrationIsRecorded() {
        UserOverrides recorded = recordAndApply(Space.STANDARD.toString(), "i1", false);

        assertEquals(1, recorded.getIntegrations().size());
        assertEquals("i1", recorded.getIntegrations().get(0).getId());
        assertEquals(Boolean.FALSE, recorded.getIntegrations().get(0).getEnabled());
        assertEquals("the request must be answered", 1, this.onDoneCalls.get());
    }

    /**
     * Re-enabling is recorded too. The registry holds the decision, not just the deviation, so a user
     * who turns an integration back on is not left at CTI's mercy for it.
     */
    public void testEnablingAStandardIntegrationIsRecorded() {
        UserOverrides recorded = recordAndApply(Space.STANDARD.toString(), "i1", true);

        assertEquals(Boolean.TRUE, recorded.getIntegrations().get(0).getEnabled());
    }

    /** Draft is never rebuilt from CTI, so nothing there belongs in the registry. */
    public void testADraftIntegrationIsNotRecorded() {
        this.action.afterResourceCommitted(
                "i1",
                Space.DRAFT.toString(),
                indexedWrapper("i1", false),
                this.onDoneCalls::incrementAndGet);

        verifyNoInteractions(this.overridesService);
        assertEquals("the request must still be answered", 1, this.onDoneCalls.get());
    }

    /** A registry failure must not fail an update that already landed. */
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

        this.action.afterResourceCommitted(
                "i1",
                Space.STANDARD.toString(),
                indexedWrapper("i1", false),
                this.onDoneCalls::incrementAndGet);

        assertEquals(1, this.onDoneCalls.get());
    }
}
