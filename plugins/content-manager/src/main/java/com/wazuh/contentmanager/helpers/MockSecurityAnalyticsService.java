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
import org.opensearch.rest.RestRequest.Method;

import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;

/**
 * Mock implementation of {@link SecurityAnalyticsService} that performs no-op for all operations.
 *
 * <p>Activated via the {@code plugins.content_manager.engine.mock_enabled} setting. Intended for
 * integration testing environments where the Security Analytics Plugin transport actions may not
 * behave as expected.
 */
public class MockSecurityAnalyticsService implements SecurityAnalyticsService {
    private static final Logger log = LogManager.getLogger(MockSecurityAnalyticsService.class);

    /** Default constructor. */
    public MockSecurityAnalyticsService() {
        log.warn("MockSecurityAnalyticsService is active. All SAP operations will be no-ops.");
    }

    @Override
    public void upsertIntegration(JsonNode doc, Space space, Method method) {
        log.debug("MockSecurityAnalyticsService.upsertIntegration called");
    }

    @Override
    public void deleteIntegration(String id, boolean isStandard) {
        log.debug("MockSecurityAnalyticsService.deleteIntegration called for id: {}", id);
    }

    @Override
    public void upsertRule(JsonNode doc, Space space) {
        log.debug("MockSecurityAnalyticsService.upsertRule called");
    }

    @Override
    public void deleteRule(String id, boolean isStandard) {
        log.debug("MockSecurityAnalyticsService.deleteRule called for id: {}", id);
    }

    @Override
    public void upsertDetector(JsonNode doc, boolean rawCategory) {
        log.debug("MockSecurityAnalyticsService.upsertDetector called");
    }

    @Override
    public void deleteDetector(String id) {
        log.debug("MockSecurityAnalyticsService.deleteDetector called for id: {}", id);
    }
}
