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
package com.wazuh.setup.settings;

import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.common.unit.TimeValue;

import java.util.concurrent.TimeUnit;

/** Settings class for this plugin. */
public class PluginSettings {

    /** Default timeout in seconds for operations involving the OpenSearch client. */
    public static final int DEFAULT_TIMEOUT = 30;

    /**
     * Default backoff (delay) time in seconds for the retry mechanism involving initialization tasks.
     */
    public static final int DEFAULT_BACKOFF = 15;

    /** Timeout setting definition. */
    public static final Setting<Integer> TIMEOUT =
            Setting.intSetting(
                    "plugins.setup.timeout", DEFAULT_TIMEOUT, 5, 120, Setting.Property.NodeScope);

    /** Backoff setting definition. */
    public static final Setting<Integer> BACKOFF =
            Setting.intSetting(
                    "plugins.setup.backoff", DEFAULT_BACKOFF, 5, 60, Setting.Property.NodeScope);

    /**
     * {@link PluginSettings#TIMEOUT} getter.
     *
     * @param settings settings of this node.
     * @return returns the value for the {@link PluginSettings#TIMEOUT} in millis.
     */
    public static long getTimeout(Settings settings) {
        return new TimeValue(TIMEOUT.get(settings), TimeUnit.SECONDS).millis();
    }

    /**
     * {@link PluginSettings#BACKOFF} getter.
     *
     * @param settings settings of this node.
     * @return returns the value for the {@link PluginSettings#BACKOFF} in millis.
     */
    public static long getBackoff(Settings settings) {
        return new TimeValue(BACKOFF.get(settings), TimeUnit.SECONDS).millis();
    }
}
