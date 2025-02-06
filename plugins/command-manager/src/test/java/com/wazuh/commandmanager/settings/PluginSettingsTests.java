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

import org.opensearch.common.settings.Settings;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import java.util.Optional;

import org.mockito.InjectMocks;
import org.mockito.Mock;

import static org.mockito.Mockito.*;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class PluginSettingsTests extends OpenSearchIntegTestCase {
@Mock private Environment mockEnvironment;

@InjectMocks private PluginSettings pluginSettings;

Settings settings;

@Before
@Override
public void setUp() throws Exception {
	settings =
		Settings.builder()
			.put("command_manager.client.timeout", 20)
			.put("command_manager.job.schedule", 1)
			.put("command_manager.job.max_docs", 100)
			.build();

	mockEnvironment = mock(Environment.class);
	when(mockEnvironment.settings()).thenReturn(settings);
	pluginSettings = PluginSettings.getInstance(mockEnvironment.settings());
	super.setUp();
}

public void testInitializeWithValidValues() throws Exception {
	pluginSettings = PluginSettings.getInstance(mockEnvironment.settings());

	assertEquals(Optional.of(20), Optional.of(pluginSettings.getTimeout()));
	assertEquals(Optional.of(1), Optional.of(pluginSettings.getJobSchedule()));
	assertEquals(Optional.of(100), Optional.of(pluginSettings.getMaxDocs()));
	assertEquals("index-template-scheduled-commands", PluginSettings.getJobIndexTemplate());
	assertEquals("/_plugins/_command_manager", PluginSettings.getApiPrefix());
	assertEquals("/_plugins/_command_manager/commands", PluginSettings.getApiCommandsEndpoint());
	assertEquals("wazuh-commands", PluginSettings.getIndexName());
	assertEquals("index-template-commands", PluginSettings.getIndexTemplate());
}

public void testSingletonBehavior() throws Exception {
	PluginSettings pluginSettings2 = PluginSettings.getInstance(mockEnvironment.settings());
	assertEquals(pluginSettings, pluginSettings2);
}

public void testSingletonMultithreadedBehavior() throws Exception {
	PluginSettings[] pluginSettingsArray = new PluginSettings[10];
	for (int i = 0; i < 10; i++) {
	pluginSettingsArray[i] = PluginSettings.getInstance(mockEnvironment.settings());
	}

	for (int i = 0; i < 10; i++) {
	assertEquals(pluginSettings, pluginSettingsArray[i]);
	}
}
}
