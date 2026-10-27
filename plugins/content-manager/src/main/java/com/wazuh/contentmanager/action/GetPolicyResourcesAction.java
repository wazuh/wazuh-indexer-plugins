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
package com.wazuh.contentmanager.action;

import org.opensearch.action.ActionType;

/** Action type for listing the resources of a space, grouped by pipeline phase. */
public class GetPolicyResourcesAction extends ActionType<GetPolicyResourcesResponse> {
    /** Read-only action, under the Content Manager monitor action group. */
    public static final String NAME = "cluster:monitor/content_manager/policy/resources/get";

    /** Singleton instance. */
    public static final GetPolicyResourcesAction INSTANCE = new GetPolicyResourcesAction();

    /** Default constructor. */
    public GetPolicyResourcesAction() {
        super(NAME, GetPolicyResourcesResponse::new);
    }
}
