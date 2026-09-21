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
package com.wazuh.contentmanager.cti.console.client;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.settings.PluginSettingsTests;

/**
 * Unit tests for the request URIs built by {@link ApiClient}. The Console endpoints must be derived
 * from the {@code plugins.content_manager.cti.api} setting, like the catalog ones, rather than from
 * a hardcoded host.
 */
public class ApiClientUriTests extends OpenSearchTestCase {

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettingsTests.clearInstance();
    }

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettingsTests.clearInstance();
        super.tearDown();
    }

    /** Every endpoint, Console and catalog alike, is built from the configured CTI base URL. */
    public void testUrisUseConfiguredBaseUrl() {
        Settings settings =
                Settings.builder()
                        .put("plugins.content_manager.cti.api", "https://cti.example.test/api/v1")
                        .build();
        PluginSettings.getInstance(settings);

        Assert.assertEquals(
                "https://cti.example.test/api/v1/instances/token", ApiClient.ctiUri(ApiClient.TOKEN_PATH));
        Assert.assertEquals(
                "https://cti.example.test/api/v1/instances/me", ApiClient.ctiUri(ApiClient.PRODUCTS_PATH));
        Assert.assertEquals(
                "https://cti.example.test/api/v1/platform/environments/me",
                ApiClient.ctiUri(ApiClient.ENVIRONMENTS_ME_PATH));
        Assert.assertEquals(
                "https://cti.example.test/api/v1/platform/environments/token/exchange",
                ApiClient.ctiUri(ApiClient.RESOURCE_PATH));
        Assert.assertEquals(
                "https://cti.example.test/api/v1/catalog/plans",
                ApiClient.ctiUri(ApiClient.CATALOG_PLANS_PATH));
    }

    /**
     * Without configuration the endpoints keep the URLs they had when the Console host was hardcoded.
     */
    public void testUrisFallBackToDefault() {
        PluginSettings.getInstance(Settings.EMPTY);

        Assert.assertEquals(
                "https://api.pre.cloud.wazuh.com/api/v1/instances/token",
                ApiClient.ctiUri(ApiClient.TOKEN_PATH));
        Assert.assertEquals(
                "https://api.pre.cloud.wazuh.com/api/v1/instances/me",
                ApiClient.ctiUri(ApiClient.PRODUCTS_PATH));
        Assert.assertEquals(
                "https://api.pre.cloud.wazuh.com/api/v1/platform/environments/me",
                ApiClient.ctiUri(ApiClient.ENVIRONMENTS_ME_PATH));
        Assert.assertEquals(
                "https://api.pre.cloud.wazuh.com/api/v1/platform/environments/token/exchange",
                ApiClient.ctiUri(ApiClient.RESOURCE_PATH));
    }
}
