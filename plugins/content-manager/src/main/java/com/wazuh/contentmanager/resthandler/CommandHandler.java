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
package com.wazuh.contentmanager.resthandler;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.client.node.NodeClient;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;

import java.io.IOException;

import static org.opensearch.rest.RestRequest.Method.POST;

public class CommandHandler extends BaseRestHandler {

    private static final Logger log = LogManager.getLogger(CommandHandler.class);
    public static final String CREATE_NEW_COMMAND = "create_new_command";

    @Override
    public String getName() {
        return CREATE_NEW_COMMAND;
    }

    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        switch (request.method()) {
            case POST:
                return restChannel -> {
                    restChannel.sendResponse();
                };
            default:
                throw new IllegalArgumentException(("Unsupported HTTP method " + request.method().name()));
        }
    }
}
