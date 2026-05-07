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
package com.wazuh.contentmanager.rest.service;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.common.SuppressForbidden;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Assert;
import org.junit.Before;

import java.lang.reflect.Field;

import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.service.PlansService;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.*;

/**
 * Unit tests for {@link RestGetSubscriptionAction}.
 *
 * <p>Validates the nested JSON response shape and correct registration state detection.
 */
public class RestGetSubscriptionActionTests extends OpenSearchTestCase {
    private PlansService plansService;
    private RestGetSubscriptionAction action;
    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        clearPluginSettingsInstance();
        PluginSettings.getInstance(org.opensearch.common.settings.Settings.EMPTY);
        this.plansService = mock(PlansService.class);
        this.action = new RestGetSubscriptionAction(this.plansService);
    }

    @After
    public void tearDown() throws Exception {
        clearPluginSettingsInstance();
        super.tearDown();
    }

    @SuppressForbidden(reason = "Unit test reset")
    private static void clearPluginSettingsInstance() throws Exception {
        Field f = PluginSettings.class.getDeclaredField("INSTANCE");
        f.setAccessible(true);
        f.set(null, null);
    }

    /**
     * Registered instance: accessToken set, getPlan() returns a plan. Response must contain plan
     * name, is_public and is_registered=true.
     */
    public void testGetSubscription200_Registered() throws Exception {
        PluginSettings.getInstance().setAccessToken("bearer-token");
        Plan plan = MAPPER.readValue("{\"name\":\"Premium Plan\",\"is_public\":false}", Plan.class);
        when(this.plansService.getPlan()).thenReturn(plan);

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.OK, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("Premium Plan"));
        Assert.assertTrue(body.contains("\"is_public\":false"));
        Assert.assertTrue(body.contains("\"is_registered\":true"));
        Assert.assertTrue(body.contains("\"status\":200"));
    }

    /**
     * Unregistered instance: accessToken null, getPlan() returns public plan. Response must contain
     * is_registered=false.
     */
    public void testGetSubscription200_Unregistered() throws Exception {
        Plan plan = MAPPER.readValue("{\"name\":\"Free\",\"is_public\":true}", Plan.class);
        when(this.plansService.getPlan()).thenReturn(plan);

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.OK, response.status());
        String body = response.content().utf8ToString();
        Assert.assertTrue(body.contains("\"is_registered\":false"));
        Assert.assertTrue(body.contains("Free"));
    }

    /** When getPlan() throws, returns 500 with the error message. */
    public void testGetSubscription500() throws Exception {
        when(this.plansService.getPlan()).thenThrow(new RuntimeException("CTI unreachable"));

        BytesRestResponse response = this.action.handleRequest();

        Assert.assertEquals(RestStatus.INTERNAL_SERVER_ERROR, response.status());
        Assert.assertTrue(response.content().utf8ToString().contains("CTI unreachable"));
    }
}
