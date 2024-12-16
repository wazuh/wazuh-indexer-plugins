/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.commandmanager.settings;

import org.opensearch.common.settings.MockSecureSettings;
import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import org.mockito.InjectMocks;
import org.mockito.Mock;

import static org.mockito.Mockito.*;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class PluginSettingsTests extends OpenSearchIntegTestCase {
    @Mock private Environment mockEnvironment;

    @InjectMocks private PluginSettings pluginSettings;

    MockSecureSettings secureSettings;

    Settings testSettings;

    @Before
    @Override
    public void setUp() throws Exception {
        secureSettings = new MockSecureSettings();
        secureSettings.setString("m_api.auth.username", "testUser");
        secureSettings.setString("m_api.auth.password", "testPassword");
        secureSettings.setString("m_api.uri", "https://httpbin.org/post");
        testSettings = Settings.builder().setSecureSettings(secureSettings).build();
        mockEnvironment = mock(Environment.class);
        when(mockEnvironment.settings()).thenReturn(testSettings);
        pluginSettings = PluginSettings.getInstance(mockEnvironment.settings());
        super.setUp();
    }

    public void testInitializeWithValidValues() throws Exception {
        // Call getSettings and expect a PluginSettings object
        pluginSettings = PluginSettings.getInstance(mockEnvironment.settings());

        assertNotNull("Expect that the PluginSettings object is not null", pluginSettings);
        assertEquals(
                "The m_api.auth.username must be the same",
                "testUser",
                pluginSettings.getAuthUsername());
        assertEquals(
                "The m_api.auth.password must be the same",
                "testPassword",
                pluginSettings.getAuthPassword());
        assertEquals(
                "The m_api.uri must be the same",
                "https://httpbin.org/post",
                pluginSettings.getUri()); // Cleanup
        secureSettings.close();
    }

    public void testSingletonBehavior() throws Exception {
        final MockSecureSettings secureSettings = new MockSecureSettings();
        PluginSettings settings1 = PluginSettings.getInstance(mockEnvironment.settings());
        PluginSettings settings2 = PluginSettings.getInstance(mockEnvironment.settings());
        assertEquals("Both instances should be the same", settings1, settings2);
    }
}
