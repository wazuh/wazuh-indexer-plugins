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

/**
 * Enum representing the indices used by Wazuh. Each enum constant contains the index name and an
 * optional alias.
 */
public enum Index {
    ALERTS("wazuh-alerts-5.x-0001", "index-template-alerts.json", "wazuh-alerts"),
    ARCHIVES("wazuh-archives-5.x-0001", "index-template-archives.json", "wazuh-archives"),
    FILES("wazuh-states-fim-files", "index-template-fim-files.json", null),
    REGISTRIES("wazuh-states-fim-registries", "index-template-fim-registries.json", null),
    HARDWARE("wazuh-states-inventory-hardware", "index-template-hardware.json", null),
    HOTFIXES("wazuh-states-inventory-hotfixes", "index-template-hotfixes.json", null),
    INTERFACES("wazuh-states-inventory-interfaces", "index-template-interfaces.json", null),
    MONITORING("wazuh-monitoring", "index-template-monitoring.json", null),
    NETWORKS("wazuh-states-inventory-networks", "index-template-networks.json", null),
    PACKAGES("wazuh-states-inventory-packages", "index-template-packages.json", null),
    PORTS("wazuh-states-inventory-ports", "index-template-ports.json", null),
    PROCESSES("wazuh-states-inventory-processes", "index-template-processes.json", null),
    PROTOCOLS("wazuh-states-inventory-protocols", "index-template-protocols.json", null),
    STATISTICS("wazuh-statistics", "index-template-statistics.json", null),
    SYSTEM("wazuh-states-inventory-system", "index-template-system.json", null),
    VULNERABILITIES("wazuh-states-vulnerabilities", "index-template-vulnerabilities.json", null);

    private final String index;
    private final String template;
    private final String alias;

    Index(String index, String template, String alias) {
        this.index = index;
        this.template = template;
        this.alias = alias;
    }

    public String getTemplate() {
        return template;
    }

    public String getIndexName() {
        return index;
    }

    public Optional<String> getAlias() {
        return Optional.ofNullable(alias);
    }
}
