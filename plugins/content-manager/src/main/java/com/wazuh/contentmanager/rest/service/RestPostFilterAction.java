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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.action.ActionType;

import java.util.List;

import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.action.CreateFilterAction;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.POST;

/** REST handler for creating Filter resources. Delegates to transport layer. */
public class RestPostFilterAction extends AbstractCreateActionSpaces {

    private static final String ENDPOINT_NAME = "content_manager_filter_create";

    public RestPostFilterAction() {
        super();
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(POST, PluginSettings.FILTERS_URI));
    }

    @Override
    protected ActionType<ContentResponse> getActionType() {
        return CreateFilterAction.INSTANCE;
    }
}
