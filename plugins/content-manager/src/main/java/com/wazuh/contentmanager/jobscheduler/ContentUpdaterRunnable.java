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
package com.wazuh.contentmanager.jobscheduler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.Client;

public class ContentUpdaterRunnable implements Runnable {
    private static final Logger log = LogManager.getLogger(ContentUpdaterRunnable.class);
    private final Client client;

    /**
     * Default constructor.
     *
     * @param client OpenSearch's client.
     */
    public ContentUpdaterRunnable(Client client) {
        this.client = client;
    }

    @Override
    public void run() {}
}
