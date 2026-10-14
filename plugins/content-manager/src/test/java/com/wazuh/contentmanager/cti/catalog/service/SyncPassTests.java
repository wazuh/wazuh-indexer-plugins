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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.service.CtiConsoleUnavailableException;
import com.wazuh.contentmanager.settings.PluginSettings;

/** Unit tests for {@link SyncPass}. */
public class SyncPassTests extends OpenSearchTestCase {

    private static final String RESOURCE =
            "https://cti.example/api/v1/catalog/contexts/pro-ruleset/consumers/pro-ruleset";

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(Settings.EMPTY);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettings.resetForTesting();
        super.tearDown();
    }

    /** An instance without a registered token has no plan, and the CTI Console is not asked. */
    public void testUnregisteredInstanceHasNoPlan() throws Exception {
        SyncPass pass = SyncPass.resolve();

        assertNull(pass.planResource("ruleset"));
    }

    /** The plan provides the resource of the feature of each consumer type, and none for others. */
    public void testPlanResourceIsTheFeatureOfTheConsumerType() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode plan = mapper.createObjectNode().put("name", "Pro");
        plan.putArray("features").addObject().put("type", "ruleset").put("resource", RESOURCE);
        SyncPass pass = SyncPass.withPlan(mapper.convertValue(plan, Plan.class));

        assertEquals(RESOURCE, pass.planResource("ruleset"));
        assertNull(pass.planResource("iocs"));
    }

    /** A plan that could not be looked up is unknown, not empty: asking for a resource fails. */
    public void testUnknownPlanHasNoAnswer() {
        SyncPass pass = SyncPass.withUnknownPlan("CTI Console unavailable");

        expectThrows(CtiConsoleUnavailableException.class, () -> pass.planResource("ruleset"));
    }

    /** A consumer the swap recorded nothing for is unchanged. */
    public void testSwapOutcomeDefaultsToUnchanged() {
        SyncPass pass = SyncPass.withPlan(null);
        pass.recordSwapOutcome("iocs", SyncPass.SwapOutcome.SWAPPED);

        assertEquals(SyncPass.SwapOutcome.SWAPPED, pass.swapOutcome("iocs"));
        assertEquals(SyncPass.SwapOutcome.UNCHANGED, pass.swapOutcome("ruleset"));
    }
}
