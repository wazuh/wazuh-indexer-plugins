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
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.action.cti.GetChangesAction;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * Handler class for the Changes endpoint exposed by the plugin This is meant for testing purposes
 * until we have a functional JobScheduler job to trigger the CTI API-related logic
 */
public class ChangesHandler extends BaseRestHandler {

    private static String FROM_OFFSET_FIELD = "from_offset";
    private static String TO_OFFSET_FIELD = "to_offset";
    private static String WITH_EMPTIES_FIELD = "with_empties";

    private static final Logger log = LogManager.getLogger(ChangesHandler.class);

    public static final String GET_CHANGES_DETAILS = "get_changes_details";

    /** Exposes the endpoint */
    @Override
    public List<Route> routes() {
        return List.of(
                new Route(
                        GET,
                        String.format(Locale.ROOT, "%s", "/_plugins/_content_manager/vd-changes")));
    }

    @Override
    public String getName() {
        return GET_CHANGES_DETAILS;
    }

    /** Handles the REST request and calls the appropriate action */
    @Override
    protected RestChannelConsumer prepareRequest(RestRequest request, NodeClient client)
            throws IOException {
        switch (request.method()) {
            case GET:
                GetChangesAction changesAction =
                        new GetChangesAction(
                                request.param(FROM_OFFSET_FIELD),
                                request.param(TO_OFFSET_FIELD),
                                request.param(WITH_EMPTIES_FIELD));
                return restChannel -> {
                    restChannel.sendResponse(changesAction.run());
                };
            default:
                throw new IllegalArgumentException(
                        ("Unsupported HTTP method " + request.method().name()));
        }
    }
}
