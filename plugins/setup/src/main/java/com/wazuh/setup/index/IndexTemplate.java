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

/** Enum representing the index templates used by Wazuh. */
public enum IndexTemplate {
    ALERTS("index-template-alerts.json"),
    ARCHIVES("index-template-archives.json"),
    FILES("index-template-fim-files.json"),
    REGISTRIES("index-template-fim-registries.json"),
    HARDWARE("index-template-hardware.json"),
    HOTFIXES("index-template-hotfixes.json"),
    INTERFACES("index-template-interfaces.json"),
    MONITORING("index-template-monitoring.json"),
    NETWORKS("index-template-networks.json"),
    PACKAGES("index-template-packages.json"),
    PORTS("index-template-ports.json"),
    PROCESSES("index-template-processes.json"),
    PROTOCOLS("index-template-protocols.json"),
    STATISTICS("index-template-statistics.json"),
    SYSTEM("index-template-system.json"),
    VULNERABILITIES("index-template-vulnerabilities.json");

    private final String templateName;

    IndexTemplate(String templateName) {
        this.templateName = templateName;
    }

    public String getTemplateName() {
        return templateName;
    }
}
