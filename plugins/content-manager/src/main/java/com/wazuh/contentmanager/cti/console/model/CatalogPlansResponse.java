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
package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

import java.util.List;

/** Response model for the {@code GET /catalog/plans} CTI Console API endpoint. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class CatalogPlansResponse {
    private List<Plan> plans;

    /** Default no-argument constructor. */
    public CatalogPlansResponse() {}

    /**
     * Retrieves the list of catalog plans.
     *
     * @return a {@link List} of {@link Plan} objects, or {@code null} if none are set.
     */
    public List<Plan> getPlans() {
        return this.plans;
    }
}
