/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.setup.settings;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

/** Unit tests for {@link PluginSettings}. */
public class PluginSettingsTests extends OpenSearchTestCase {

    /**
     * The retry count used to be a boolean flipped once, allowing exactly one re-attempt. The default
     * must preserve that, so an untouched opensearch.yml keeps the behaviour of the previous release.
     */
    public void testMaxRetriesDefaultsToOneReattempt() {
        Assert.assertEquals(1, PluginSettings.getMaxRetries(Settings.EMPTY));
    }

    /** The existing timeout and backoff defaults are unchanged by the retry-count promotion. */
    public void testTimeoutAndBackoffDefaultsUnchanged() {
        Assert.assertEquals(30_000L, PluginSettings.getTimeout(Settings.EMPTY));
        Assert.assertEquals(15_000L, PluginSettings.getBackoff(Settings.EMPTY));
    }

    /** A configured retry count must win over the default. */
    public void testMaxRetriesReadsCustomValue() {
        Settings settings = Settings.builder().put("plugins.setup.max_retries", 5).build();
        Assert.assertEquals(5, PluginSettings.getMaxRetries(settings));
    }

    /** Zero is a valid setting: it disables retrying entirely. */
    public void testMaxRetriesAcceptsZero() {
        Settings settings = Settings.builder().put("plugins.setup.max_retries", 0).build();
        Assert.assertEquals(0, PluginSettings.getMaxRetries(settings));
    }

    /** A negative retry count is rejected rather than silently clamped. */
    public void testMaxRetriesBelowMinThrows() {
        Settings settings = Settings.builder().put("plugins.setup.max_retries", -1).build();
        Assert.assertThrows(
                IllegalArgumentException.class, () -> PluginSettings.getMaxRetries(settings));
    }

    /**
     * A retry count above the maximum is rejected. Each re-attempt costs a backoff sleep on the node
     * startup path, so an unbounded value would stall the node instead of failing it.
     */
    public void testMaxRetriesAboveMaxThrows() {
        Settings settings = Settings.builder().put("plugins.setup.max_retries", 11).build();
        Assert.assertThrows(
                IllegalArgumentException.class, () -> PluginSettings.getMaxRetries(settings));
    }
}
