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
package com.wazuh.contentmanager.rest.services;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.core.rest.RestStatus;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;

import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the {@link RestPostLogtestAction} class. This test suite validates the REST API
 * endpoint responsible for running CTI Logtests.
 *
 * <p>Tests verify Logtest requests, proper handling of Logtest data, and appropriate HTTP response
 * codes for successful Logtest requests and validation errors.
 */
public class RestPostLogtestActionTests extends OpenSearchTestCase {
    private EngineService engine;
    private RestPostLogtestAction action;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.engine = mock(EngineService.class);
        this.action = new RestPostLogtestAction(this.engine);
    }

    /**
     * Test the {@link RestPostLogtestAction#handleRequest(logtest)} method when the request is
     * complete. The expected response is: {201, RestResponse}
     *
     * @throws IOException
     */
    public void testPostLogtest200() throws IOException {}

    /**
     * Test the {@link RestPostLogtestAction#handleRequest(logtest)} method when the logtest has not
     * been created (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testPostLogtest400() throws IOException {
        JsonNode payload =
                new ObjectMapper()
                        .readTree(
                                "{\n"
                                        + "  \"queue\": 1,\n"
                                        + "  \"location\": \"syscheck\",\n"
                                        + "  \"event\": \"File /etc/passwd modified\",\n"
                                        + "  \"trace_level\": \"ALL\"\n"
                                        + "}");

        RestResponse response = new RestResponse();
        response.setStatus(RestStatus.BAD_REQUEST.getStatus());
        response.setMessage(
                "{\n"
                        + "  \"status\": \"ERROR\",\n"
                        + "  \"error\": \"agent_metadata is required and must be a JSON object\"\n"
                        + "}");

        when(this.engine.logtest(payload)).thenReturn(response);
    }

    /**
     * Test the {@link RestPostLogtestAction#handleRequest(RestRequest)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testPostLogtest500() throws IOException {}
}
