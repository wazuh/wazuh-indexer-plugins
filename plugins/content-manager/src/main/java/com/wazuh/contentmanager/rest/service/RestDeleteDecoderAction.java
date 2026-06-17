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
import com.wazuh.contentmanager.action.DeleteDecoderAction;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.opensearch.rest.RestRequest.Method.DELETE;

/** REST handler for deleting Decoder resources. Delegates to transport layer. */
public class RestDeleteDecoderAction extends AbstractDeleteAction {

    private static final String ENDPOINT_NAME = "content_manager_decoder_delete";

    public RestDeleteDecoderAction() {
        super();
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(new Route(DELETE, PluginSettings.DECODERS_URI + "/{id}"));
    }

    @Override
    protected ActionType<ContentResponse> getActionType() {
        return DeleteDecoderAction.INSTANCE;
    }
}
