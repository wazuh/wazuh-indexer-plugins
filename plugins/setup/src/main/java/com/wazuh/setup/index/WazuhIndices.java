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
package com.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.transport.client.Client;

/**
 * This class contains the logic to create the index templates and the indices required by Wazuh.
 */
public class WazuhIndices {
    private static final Logger log = LogManager.getLogger(WazuhIndices.class);

    private final Client client;
    private final RoutingTable routingTable;

    /**
     * Constructor
     *
     * @param client Client
     * @param routingTable RoutingTable object
     */
    public WazuhIndices(Client client, RoutingTable routingTable) {
        this.client = client;
        this.routingTable = routingTable;
    }

    /**
     * Initializes the Wazuh indices by creating the necessary index templates and indices. This
     * method should be called when the plugin is started.
     */
    public void initialize() {
        WazuhIndexInitializer wazuhIndex =
                WazuhIndexInitializer.getInstance()
                        .setClient(this.client)
                        .setRoutingTable(this.routingTable);
        IsmIndexInitializer ismIndex =
                IsmIndexInitializer.getInstance().setClient(this.client).setRoutingTable(this.routingTable);
        for (Index value : Index.values()) {
            value.initIndex();
        }
    }
}
