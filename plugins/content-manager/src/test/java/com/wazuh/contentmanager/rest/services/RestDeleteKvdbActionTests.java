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

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Before;

import java.io.IOException;

import com.wazuh.contentmanager.engine.services.EngineService;

import static org.mockito.Mockito.mock;

/**
 * Unit tests for the {@link RestDeleteKvdbAction} class. This test suite validates the REST API
 * endpoint responsible for deleting new CTI Kvdbs.
 *
 * <p>Tests verify Kvdb delete requests, proper handling of Kvdb data, and appropriate HTTP response
 * codes for successful Kvdb delete errors.
 */
public class RestDeleteKvdbActionTests extends OpenSearchTestCase {
    private EngineService service;
    private RestDeleteKvdbAction action;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.service = mock(EngineService.class);
        this.action = new RestDeleteKvdbAction(this.service);
    }

    /**
     * Test the {@link RestDeleteKvdbAction#handleRequest(kvdb)} method when the request is complete.
     * The expected response is: {201, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteKvdb201() throws IOException {}

    /**
     * Test the {@link RestDeleteKvdbAction#handleRequest(kvdb)} method when the kvdb has not been
     * deleted (mock). The expected response is: {400, RestResponse}
     *
     * @throws IOException
     */
    public void testDeleteKvdb400() throws IOException {}

    /**
     * Test the {@link RestDeleteKvdbAction#handleRequest(RestRequest)} method when an unexpected
     * error occurs. The expected response is: {500, RestResponse}
     *
     * @throws IOException if an I/O error occurs during the test
     */
    public void testDeleteKvdb500() throws IOException {}
}
