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
package com.wazuh.contentmanager.action.cti;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.*;
import org.opensearch.rest.BytesRestResponse;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

import com.wazuh.contentmanager.client.commandmanager.CommandManagerClient;
import com.wazuh.contentmanager.client.cti.CTIClient;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.Offsets;
import com.wazuh.contentmanager.util.Privileged;

/**
 * Action class handling Offsets logic. This is used to get the json patches to the current
 * vulnerability data
 */
public class GetChangesAction {
    private static final Logger log = LogManager.getLogger(GetChangesAction.class);

    private static String FROM_OFFSET_FIELD = "from_offset";
    private static String TO_OFFSET_FIELD = "to_offset";
    private static String WITH_EMPTIES_FIELD = "with_empties";
    private String fromOffset = null;
    private String toOffset = null;
    private String withEmpties = null;

    /** Constructor method */
    public GetChangesAction(String fromOffset, String toOffset, String withEmpties) {
        this.fromOffset = fromOffset;
        this.toOffset = toOffset;
        this.withEmpties = withEmpties;
    }

    /**
     * Submits a changes query to the CTI API
     *
     * @return The parsed response from the CTI API
     * @throws IOException rethrown from parse()
     * @throws IllegalArgumentException rethrown from parse()
     */
    public BytesRestResponse run() throws IOException, IllegalArgumentException {
        XContent xContent = XContentType.JSON.xContent();
        XContentBuilder builder = XContentFactory.jsonBuilder();
        SimpleHttpResponse response =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getChanges());
        Offsets.parse(
                        xContent.createParser(
                                NamedXContentRegistry.EMPTY,
                                DeprecationHandler.IGNORE_DEPRECATIONS,
                                response.getBodyBytes()))
                .toXContent(builder, ToXContent.EMPTY_PARAMS);
        SimpleHttpResponse commandResponse =
                CommandManagerClient.getInstance()
                        .postCommand(Command.generateCtiCommand("Offset_version"));
        log.info("Command Manager response: {}", commandResponse);
        return new BytesRestResponse(RestStatus.fromCode(response.getCode()), builder.toString());
    }

    /**
     * Builds a Map with the query parameters for the CTI API call
     *
     * @return The map with the parameters
     */
    private Map<String, String> buildQueryParametersMap() {
        Map<String, String> params = new HashMap<>();
        params.put(FROM_OFFSET_FIELD, fromOffset);
        params.put(TO_OFFSET_FIELD, toOffset);
        params.put(WITH_EMPTIES_FIELD, withEmpties);
        return params;
    }
}
