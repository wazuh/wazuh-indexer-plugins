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

import org.opensearch.cluster.routing.RoutingTable;
import org.opensearch.transport.client.Client;

import java.util.Optional;

/**
 * Enum representing the indices used by Wazuh. Each enum constant corresponds to a specific index name,
 * its template file, an optional alias and the initializer responsible for managing that index.
 */
public enum Index {
    ISM(".opendistro-ism-config", "opendistro-ism-config.json", null, Initializers.ISM),
    ALERTS("wazuh-alerts-5.x-0001", "index-template-alerts.json", "wazuh-alerts", Initializers.WAZUH),
    ARCHIVES(
            "wazuh-archives-5.x-0001",
            "index-template-archives.json",
            "wazuh-archives",
            Initializers.WAZUH),
    FILES("wazuh-states-fim-files", "index-template-fim-files.json", null, Initializers.WAZUH),
    REGISTRIES(
            "wazuh-states-fim-registries",
            "index-template-fim-registries.json",
            null,
            Initializers.WAZUH),
    HARDWARE(
            "wazuh-states-inventory-hardware", "index-template-hardware.json", null, Initializers.WAZUH),
    HOTFIXES(
            "wazuh-states-inventory-hotfixes", "index-template-hotfixes.json", null, Initializers.WAZUH),
    INTERFACES(
            "wazuh-states-inventory-interfaces",
            "index-template-interfaces.json",
            null,
            Initializers.WAZUH),
    MONITORING("wazuh-monitoring", "index-template-monitoring.json", null, Initializers.WAZUH),
    NETWORKS(
            "wazuh-states-inventory-networks", "index-template-networks.json", null, Initializers.WAZUH),
    PACKAGES(
            "wazuh-states-inventory-packages", "index-template-packages.json", null, Initializers.WAZUH),
    PORTS("wazuh-states-inventory-ports", "index-template-ports.json", null, Initializers.WAZUH),
    PROCESSES(
            "wazuh-states-inventory-processes",
            "index-template-processes.json",
            null,
            Initializers.WAZUH),
    PROTOCOLS(
            "wazuh-states-inventory-protocols",
            "index-template-protocols.json",
            null,
            Initializers.WAZUH),
    STATISTICS("wazuh-statistics", "index-template-statistics.json", null, Initializers.WAZUH),
    SYSTEM("wazuh-states-inventory-system", "index-template-system.json", null, Initializers.WAZUH),
    VULNERABILITIES(
            "wazuh-states-vulnerabilities",
            "index-template-vulnerabilities.json",
            null,
            Initializers.WAZUH);

    private final String index;
    private final String template;
    private final String alias;
    private final IndexInitializer indexInitializer;

    Index(String index, String template, String alias, IndexInitializer indexInitializer) {
        this.index = index;
        this.template = template;
        this.alias = alias;
        this.indexInitializer = indexInitializer;
    }

    /**
     * Returns the index template file name.
     *
     * @return the index template file name
     */
    public String getTemplate() {
        return template;
    }

    /**
     * Returns the index name.
     *
     * @return the index name
     */
    public String getIndexName() {
        return index;
    }

    /**
     * Returns the alias for the index, if it exists.
     *
     * @return an Optional containing the alias if it exists, or an empty Optional if it does not
     */
    public Optional<String> getAlias() {
        return Optional.ofNullable(alias);
    }

    /** Runs the initIndex() method of the index initializer. */
    public void initIndex() {
        this.indexInitializer.initIndex(this);
    }

    /** Static subclass to setup the index initializers. */
    public static class Initializers {
        private static WazuhIndicesInitializer WAZUH;
        private static IsmIndexInitializer ISM;

        /**
         * Sets up the index initializers with the provided client and routing table. This method should
         * be called before initializing any indices.
         *
         * @param client the OpenSearch client
         * @param routingTable the routing table of the cluster
         */
        public static void setup(Client client, RoutingTable routingTable) {
            ISM = IsmIndexInitializer.getInstance().setClient(client).setRoutingTable(routingTable);
            WAZUH = WazuhIndicesInitializer.getInstance().setClient(client).setRoutingTable(routingTable);
        }

        /**
         * Public method to set the Wazuh index initializer in unit tests
         *
         * @param initializer the Wazuh indices initializer to set
         */
        public static void setWazuhIndexInitializer(WazuhIndicesInitializer initializer) {
            WAZUH = initializer;
        }

        /**
         * Public method to set the ISM index initializer in unit tests
         *
         * @param initializer the ISM index initializer to set
         */
        public static void setIsmIndexInitializer(IsmIndexInitializer initializer) {
            ISM = initializer;
        }
    }
}
