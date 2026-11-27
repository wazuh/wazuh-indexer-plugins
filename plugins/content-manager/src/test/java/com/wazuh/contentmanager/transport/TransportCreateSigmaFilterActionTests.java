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
package com.wazuh.contentmanager.transport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.test.OpenSearchTestCase;

import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;

/** Unit tests for the payload validation of {@link TransportCreateSigmaFilterAction}. */
public class TransportCreateSigmaFilterActionTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final PayloadValidations VALIDATIONS = new PayloadValidations();

    private static JsonNode payload(String space, String resource) throws Exception {
        return MAPPER.readTree(
                ("{'space':'" + space + "','resource':" + resource + "}").replace('\'', '"'));
    }

    private static String filter(String metadata, String body) {
        return "{"
                + metadata
                + "'logsource':{'product':'apache-http'},"
                + "'filter':{'rules':['26a8d32e-0838-5589-948c-501b5a301cf5'],"
                + body
                + "}}";
    }

    private static final String TITLE = "'metadata':{'title':'Ignore the scanner'},";
    private static final String NOT_SELECTION =
            "'selection':{'user_agent.original|startswith':'internal-scanner'},'condition':'not selection'";

    private static RestResponse validate(JsonNode root) {
        return TransportCreateSigmaFilterAction.validateSigmaFilter(
                root, root.get("resource"), VALIDATIONS);
    }

    public void testAValidDraftFilterIsAccepted() throws Exception {
        assertNull(validate(payload("draft", filter(TITLE, NOT_SELECTION))));
    }

    public void testOnlyTheDraftSpaceIsAccepted() throws Exception {
        for (String space : new String[] {"test", "custom", "standard", ""}) {
            RestResponse response = validate(payload(space, filter(TITLE, NOT_SELECTION)));
            assertEquals(space, 400, response.getStatus());
        }
    }

    public void testTheTitleIsRequired() throws Exception {
        RestResponse response = validate(payload("draft", filter("", NOT_SELECTION)));

        assertEquals(400, response.getStatus());
        assertTrue(response.getMessage(), response.getMessage().contains("metadata"));
    }

    public void testTheOtherConventionIsRejectedWithItsReason() throws Exception {
        RestResponse response =
                validate(
                        payload(
                                "draft", filter(TITLE, "'selection':{'user.name':'adm'},'condition':'selection'")));

        assertEquals(400, response.getStatus());
        assertTrue(
                response.getMessage(),
                response.getMessage().contains("must be a single 'not' over the filter's selections"));
    }
}
