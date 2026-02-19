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
package com.wazuh.contentmanager.helpers;

import com.fasterxml.jackson.databind.JsonNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;

import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;

/**
 * Mock implementation of {@link EngineService} that returns success for all operations.
 *
 * <p>Activated via the {@code plugins.content_manager.engine.mock_enabled} setting. Intended for
 * integration testing environments where the Wazuh Engine socket is not available.
 */
public class MockEngineService implements EngineService {
    private static final Logger log = LogManager.getLogger(MockEngineService.class);

    /** Default constructor. */
    public MockEngineService() {
        log.warn("MockEngineService is active. All engine validations will return OK.");
    }

    @Override
    public RestResponse logtest(JsonNode logEntry) {
        log.debug("MockEngineService.logtest called");
        return new RestResponse("OK", RestStatus.OK.getStatus());
    }

    @Override
    public RestResponse validate(JsonNode resource) {
        log.debug("MockEngineService.validate called");
        return new RestResponse("OK", RestStatus.OK.getStatus());
    }

    @Override
    public RestResponse promote(JsonNode policy) {
        log.debug("MockEngineService.promote called");
        return new RestResponse("OK", RestStatus.OK.getStatus());
    }

    @Override
    public RestResponse validateResource(String type, JsonNode resource) {
        log.debug("MockEngineService.validateResource called for type: {}", type);
        return new RestResponse("OK", RestStatus.OK.getStatus());
    }
}
