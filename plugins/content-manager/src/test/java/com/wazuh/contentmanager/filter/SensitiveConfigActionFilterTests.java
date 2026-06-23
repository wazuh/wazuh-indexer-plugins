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

    private final SensitiveConfigActionFilter filter = new SensitiveConfigActionFilter();

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettings.resetForTesting();
        super.tearDown();
    }

    private void lock(boolean locked) {
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(
                Settings.builder().put("plugins.content_manager.sensitive_config.locked", locked).build());
    }

    @SuppressWarnings("unchecked")
    public void testBlocksProtectedActionsWhenLocked() {
        this.lock(true);
        for (String action :
                new String[] {"plugin:content_manager/policy/put", "plugin:content_manager/update/post"}) {
            ActionListener<Object> listener = mock(ActionListener.class);
            boolean proceed = this.filter.apply(action, mock(ActionRequest.class), listener);
            assertFalse("expected " + action + " to be blocked", proceed);
            verify(listener).onFailure(any(OpenSearchStatusException.class));
        }
    }

    @SuppressWarnings("unchecked")
    public void testAllowsProtectedActionWhenUnlocked() {
        this.lock(false);
        ActionListener<Object> listener = mock(ActionListener.class);
        boolean proceed =
                this.filter.apply("plugin:content_manager/policy/put", mock(ActionRequest.class), listener);
        assertTrue(proceed);
        verify(listener, never()).onFailure(any());
    }

    @SuppressWarnings("unchecked")
    public void testIgnoresUnprotectedActionWhenLocked() {
        this.lock(true);
        ActionListener<Object> listener = mock(ActionListener.class);
        boolean proceed =
                this.filter.apply("indices:data/write/index", mock(ActionRequest.class), listener);
        assertTrue(proceed);
        verify(listener, never()).onFailure(any());
    }
}
