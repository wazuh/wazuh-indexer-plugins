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
package com.wazuh.contentmanager.rest.utils;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.OpenSearchTestCase;

import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

/** Unit tests for {@link PayloadValidations#validateDetector(JsonNode)}. */
public class PayloadValidationsTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private PayloadValidations validations;

    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.validations = new PayloadValidations();
    }

    private JsonNode parse(String json) throws Exception {
        return MAPPER.readTree(json);
    }

    private String detectorJson(String source, String interval, String enabled) {
        StringBuilder sb = new StringBuilder("{\"detector\":{");
        boolean first = true;
        if (source != null) {
            sb.append("\"source\":").append(source);
            first = false;
        }
        if (interval != null) {
            if (!first) sb.append(',');
            sb.append("\"interval\":").append(interval);
            first = false;
        }
        if (enabled != null) {
            if (!first) sb.append(',');
            sb.append("\"enabled\":").append(enabled);
        }
        sb.append("}}");
        return sb.toString();
    }

    public void testValidateDetector_absent_returnsNull() throws Exception {
        assertNull(this.validations.validateDetector(parse("{\"category\":\"security\"}")));
    }

    public void testValidateDetector_nullResource_returnsNull() {
        assertNull(this.validations.validateDetector(null));
    }

    public void testValidateDetector_validAllFields_returnsNull() throws Exception {
        String json = detectorJson("[\"wazuh-events-v5-security\"]", "5", "true");
        assertNull(this.validations.validateDetector(parse(json)));
    }

    public void testValidateDetector_validWildcardSource_returnsNull() throws Exception {
        String json = detectorJson("[\"wazuh-events-v5*\"]", "1", "false");
        assertNull(this.validations.validateDetector(parse(json)));
    }

    public void testValidateDetector_multipleValidSources_returnsNull() throws Exception {
        String json =
                detectorJson(
                        "[\"wazuh-events-v5-security\",\"wazuh-events-v5-applications\"]", "2", "true");
        assertNull(this.validations.validateDetector(parse(json)));
    }

    public void testValidateDetector_missingSource_returnsBadRequest() throws Exception {
        RestResponse response =
                this.validations.validateDetector(parse(detectorJson(null, "2", "true")));
        assertNotNull(response);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_MISSING_DETECTOR_FIELDS, response.getMessage());
    }

    public void testValidateDetector_missingInterval_returnsBadRequest() throws Exception {
        RestResponse response =
                this.validations.validateDetector(
                        parse(detectorJson("[\"wazuh-events-v5-security\"]", null, "true")));
        assertNotNull(response);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_MISSING_DETECTOR_FIELDS, response.getMessage());
    }

    public void testValidateDetector_missingEnabled_returnsBadRequest() throws Exception {
        RestResponse response =
                this.validations.validateDetector(
                        parse(detectorJson("[\"wazuh-events-v5-security\"]", "2", null)));
        assertNotNull(response);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_MISSING_DETECTOR_FIELDS, response.getMessage());
    }

    public void testValidateDetector_invalidSource_returnsBadRequest() throws Exception {
        RestResponse response =
                this.validations.validateDetector(
                        parse(detectorJson("[\"not-a-valid-index\"]", "2", "true")));
        assertNotNull(response);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertTrue(response.getMessage().contains("not-a-valid-index"));
    }

    public void testValidateDetector_zeroInterval_returnsBadRequest() throws Exception {
        RestResponse response =
                this.validations.validateDetector(
                        parse(detectorJson("[\"wazuh-events-v5-security\"]", "0", "true")));
        assertNotNull(response);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_INVALID_DETECTOR_INTERVAL, response.getMessage());
    }

    public void testValidateDetector_negativeInterval_returnsBadRequest() throws Exception {
        RestResponse response =
                this.validations.validateDetector(
                        parse(detectorJson("[\"wazuh-events-v5-security\"]", "-1", "true")));
        assertNotNull(response);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_INVALID_DETECTOR_INTERVAL, response.getMessage());
    }

    public void testValidateDetector_stringInterval_returnsBadRequest() throws Exception {
        RestResponse response =
                this.validations.validateDetector(
                        parse(detectorJson("[\"wazuh-events-v5-security\"]", "\"five\"", "true")));
        assertNotNull(response);
        assertEquals(RestStatus.BAD_REQUEST.getStatus(), response.getStatus());
        assertEquals(Constants.E_400_INVALID_DETECTOR_INTERVAL, response.getMessage());
    }
}
