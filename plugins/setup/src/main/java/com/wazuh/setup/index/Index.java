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

import java.util.Optional;

public enum Indices {
    ALERTS("wazuh-alerts-5.x-0001", "wazuh-alerts"),
    ARCHIVES("wazuh-archives-5.x-0001", "wazuh-archives"),
    FILES("wazuh-states-fim-files", null),
    REGISTRIES("wazuh-states-fim-registries", null),
    HARDWARE("wazuh-states-inventory-hardware", null),
    HOTFIXES("wazuh-states-inventory-hotfixes", null),
    INTERFACES("wazuh-states-inventory-interfaces", null),
    ISM(".opendistro-ism-config", null),
    MONITORING("wazuh-monitoring", null),
    NETWORKS("wazuh-states-inventory-networks", null),
    PACKAGES("wazuh-states-inventory-packages", null),
    PORTS("wazuh-states-inventory-ports", null),
    PROCESSES("wazuh-states-inventory-processes", null),
    PROTOCOLS("wazuh-states-inventory-protocols", null),
    STATISTICS("wazuh-statistics", null),
    SYSTEM("wazuh-states-inventory-system", null),
    VULNERABILITIES("wazuh-states-vulnerabilities", null);

    private final String index;
    private final String alias;

    Indices(String index, String alias) {
        this.index = index;
        this.alias = alias;
    }

    public String getIndexName() {
        return index;
    }

    public Optional<String> getAlias() {
        return Optional.ofNullable(alias);
    }
}
