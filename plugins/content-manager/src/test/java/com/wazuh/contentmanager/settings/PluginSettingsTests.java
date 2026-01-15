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
package com.wazuh.contentmanager.settings;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import java.lang.reflect.Field;

public class PluginSettingsTests extends OpenSearchTestCase {

    /**
     * Set up the tests. Resets the singleton instance before each test to ensure isolation.
     *
     * @throws Exception rethrown from parent method or reflection operations
     */
    @Before
    public void setUp() throws Exception {
        super.setUp();
        clearInstance();
    }

    /**
     * Tear down the tests. Resets the singleton instance after each test to ensure isolation.
     *
     * @throws Exception rethrown from parent method or reflection operations
     */
    @After
    public void tearDown() throws Exception {
        clearInstance();
        super.tearDown();
    }

    /**
     * Helper method to reset the Singleton instance of PluginSettings via reflection.
     *
     * @throws Exception if reflection fails
     */
    @SuppressForbidden(reason = "Unit test reset")
    public static void clearInstance() throws Exception {
        Field instance = PluginSettings.class.getDeclaredField("INSTANCE");
        instance.setAccessible(true);
        instance.set(null, null);
    }

    /**
     * Test the default values of the settings. Verifies that update_on_start and update_on_schedule
     * are true by default.
     */
    public void testDefaultSettings() {
        // Initialize with empty settings
        PluginSettings pluginSettings = PluginSettings.getInstance(Settings.EMPTY);

        // Verify default values
        assertTrue(pluginSettings.isUpdateOnStart());
        assertTrue(pluginSettings.isUpdateOnSchedule());
    }

    /**
     * Test custom values for the settings. Verifies that the settings correctly reflect the provided
     * configuration.
     */
    public void testCustomSettings() {
        // Initialize with custom settings
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.catalog.update_on_start", false)
                        .put("plugins.content_manager.catalog.update_on_schedule", false)
                        .build();

        PluginSettings pluginSettings = PluginSettings.getInstance(settings);

        // Verify custom values
        assertFalse(pluginSettings.isUpdateOnStart());
        assertFalse(pluginSettings.isUpdateOnSchedule());
    }
}
