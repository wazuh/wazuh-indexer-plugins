/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
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

    Settings testSettings;

    @Before
    @Override
    public void setUp() throws Exception {
        mockEnvironment = mock(Environment.class);
        pluginSettings = PluginSettings.getInstance(mockEnvironment.settings());
        super.setUp();
    }

    public void testInitializeWithValidValues() throws Exception {
        final MockSecureSettings secureSettings = new MockSecureSettings();
        try {
            secureSettings.setString("m_api.auth.username", "testUser");
            secureSettings.setString("m_api.auth.password", "testPassword");
            secureSettings.setString("m_api.uri", "https://httpbin.org/post");
            testSettings = Settings.builder().setSecureSettings(secureSettings).build();
        } finally {
            when(mockEnvironment.settings()).thenReturn(testSettings);

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
    }

    public void testSingletonBehavior() throws Exception {
        final MockSecureSettings secureSettings = new MockSecureSettings();
        try {
            secureSettings.setString("m_api.auth.username", "testUser");
            testSettings = Settings.builder().setSecureSettings(secureSettings).build();
        } finally {
            when(mockEnvironment.settings()).thenReturn(testSettings);

            PluginSettings settings1 = PluginSettings.getInstance(mockEnvironment.settings());
            PluginSettings settings2 = PluginSettings.getInstance(mockEnvironment.settings());
            assertEquals("Both instances should be the same", settings1, settings2);
        }
    }
}
