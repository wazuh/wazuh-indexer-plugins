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
public class CommandManagerSettingsTests extends OpenSearchIntegTestCase {
    @Mock private Environment mockEnvironment;

    @InjectMocks private CommandManagerSettings commandManagerSettings;

    Settings testSettings;

    @Before
    @Override
    public void setUp() throws Exception {
        mockEnvironment = mock(Environment.class);
        commandManagerSettings = CommandManagerSettings.getInstance(mockEnvironment);
        super.setUp();
    }

    public void testGetSettingsWithValidValues() throws Exception {
        final MockSecureSettings secureSettings = new MockSecureSettings();
        try {
            secureSettings.setString("m_api.auth.username", "testUser");
            secureSettings.setString("m_api.auth.password", "testPassword");
            secureSettings.setString("m_api.uri", "https://httpbin.org/post");
            testSettings = Settings.builder().setSecureSettings(secureSettings).build();
        } finally {
            when(mockEnvironment.settings()).thenReturn(testSettings);

            // Call getSettings and expect a CommandManagerSettings object
            commandManagerSettings = CommandManagerSettings.getSettings(mockEnvironment);

            assertNotNull(
                    "Expect that the CommandManagerSettings object is not null",
                    commandManagerSettings);
            assertEquals(
                    "The m_api.auth.username must be the same",
                    "testUser",
                    commandManagerSettings.getAuthUsername());
            assertEquals(
                    "The m_api.auth.password must be the same",
                    "testPassword",
                    commandManagerSettings.getAuthPassword());
            assertEquals(
                    "The m_api.uri must be the same",
                    "https://httpbin.org/post",
                    commandManagerSettings.getUri()); // Cleanup
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

            CommandManagerSettings settings1 = CommandManagerSettings.getInstance(mockEnvironment);
            CommandManagerSettings settings2 = CommandManagerSettings.getInstance(mockEnvironment);
            assertEquals("Both instances should be the same", settings1, settings2);
        }
    }
}
