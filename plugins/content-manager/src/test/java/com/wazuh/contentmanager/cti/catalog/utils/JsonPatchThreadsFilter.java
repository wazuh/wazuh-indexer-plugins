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
package com.wazuh.contentmanager.cti.catalog.utils;

import com.carrotsearch.randomizedtesting.ThreadFilter;

/**
 * Ignores the threads the json-patch library leaves behind. Its message bundles (msg-simple) load
 * their texts on fixed pools of daemon threads that are never shut down, started the first time the
 * library builds an error message. A suite that makes a patch fail must declare this filter, or the
 * thread leak checker fails it.
 */
public class JsonPatchThreadsFilter implements ThreadFilter {

    @Override
    public boolean reject(Thread t) {
        // Named by Executors.defaultThreadFactory(), made daemon by msg-simple's thread factory.
        return t.isDaemon() && t.getName().matches("pool-\\d+-thread-\\d+");
    }
}
