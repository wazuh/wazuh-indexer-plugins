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
package com.wazuh.contentmanager.filter;

import org.opensearch.OpenSearchStatusException;
import org.opensearch.action.ActionRequest;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;

import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/** Unit tests for {@link SensitiveConfigActionFilter}. */
public class SensitiveConfigActionFilterTests extends OpenSearchTestCase {

    private static final String POLICY_ACTION = "indices:data/write/content_manager/policy/update";
    private static final String UPDATE_ACTION = "cluster:admin/content_manager/update/trigger";

    private final SensitiveConfigActionFilter filter = new SensitiveConfigActionFilter();

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettings.resetForTesting();
        super.tearDown();
    }

    private void configure(boolean updateOnDemand, boolean policyUpdate) {
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(
                Settings.builder()
                        .put("plugins.content_manager.catalog.update_on_demand", updateOnDemand)
                        .put("plugins.content_manager.catalog.policy_update.enabled", policyUpdate)
                        .build());
    }

    @SuppressWarnings("unchecked")
    private void assertBlocked(String action) {
        ActionListener<Object> listener = mock(ActionListener.class);
        boolean proceed = this.filter.apply(action, mock(ActionRequest.class), listener);
        assertFalse("expected " + action + " to be blocked", proceed);
        verify(listener).onFailure(any(OpenSearchStatusException.class));
    }

    @SuppressWarnings("unchecked")
    private void assertAllowed(String action) {
        ActionListener<Object> listener = mock(ActionListener.class);
        boolean proceed = this.filter.apply(action, mock(ActionRequest.class), listener);
        assertTrue("expected " + action + " to be allowed", proceed);
        verify(listener, never()).onFailure(any());
    }

    public void testBlocksUpdateWhenUpdateOnDemandDisabled() {
        this.configure(false, true);
        this.assertBlocked(UPDATE_ACTION);
    }

    public void testBlocksPolicyWhenPolicyUpdateDisabled() {
        this.configure(true, false);
        this.assertBlocked(POLICY_ACTION);
    }

    public void testAllowsActionsWhenEnabled() {
        this.configure(true, true);
        this.assertAllowed(UPDATE_ACTION);
        this.assertAllowed(POLICY_ACTION);
    }

    public void testSettingsAreIndependent() {
        // Disabling the update trigger must not affect policy updates, and vice versa.
        this.configure(false, true);
        this.assertBlocked(UPDATE_ACTION);
        this.assertAllowed(POLICY_ACTION);

        this.configure(true, false);
        this.assertAllowed(UPDATE_ACTION);
        this.assertBlocked(POLICY_ACTION);
    }

    public void testIgnoresUnprotectedAction() {
        this.configure(false, false);
        this.assertAllowed("indices:data/write/index");
    }
}
