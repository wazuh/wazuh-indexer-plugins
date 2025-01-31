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
package com.wazuh.contentmanager.model.ctiapi;

public enum ContextConsumerCatalogEnum {
    ID("id"),
    CONTEXT("context"),
    NAME("name"),
    LAST_OFFSET("last_offset"),
    PATHS_FILTER("pathds_filter"),
    LAST_SNAPSHOT_LINK("last_snapshot_link"),
    LAST_SNAPSHOT_OFFSET("last_snapshot_offset"),
    LAST_SNAPSHOT_AT("last_snapshot_at"),
    CHANGES_URL("changes_url"),
    INSERTED_AT("inserted_at");

    ContextConsumerCatalogEnum(String string) {}
}
