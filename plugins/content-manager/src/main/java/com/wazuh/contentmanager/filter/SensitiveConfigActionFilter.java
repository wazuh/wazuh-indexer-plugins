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
import org.opensearch.action.support.ActionFilter;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;

import java.util.Set;

import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Action filter that blocks modification of sensitive Content Manager configuration when {@code
 * plugins.content_manager.sensitive_config.locked} is enabled.
 *
 * <p>When locked, the protected transport actions fail with {@code 403 FORBIDDEN} for every caller,
 * regardless of role. This is decoupled from the transport-action implementations: it matches them
 * by action name (the same names the security plugin enforces as cluster permissions), so it works
 * regardless of which class owns the action.
 */
public class SensitiveConfigActionFilter extends ActionFilter.Simple {

    /** Transport-action names whose modification is gated by the lockdown setting. */
    private static final Set<String> PROTECTED_ACTIONS =
            Set.of("plugin:content_manager/policy/put", "plugin:content_manager/update/post");

    @Override
    public int order() {
        return 0;
    }

    @Override
    protected boolean apply(String action, ActionRequest request, ActionListener<?> listener) {
        if (PROTECTED_ACTIONS.contains(action) && isLocked()) {
            listener.onFailure(
                    new OpenSearchStatusException(
                            Constants.E_403_SENSITIVE_CONFIG_LOCKED, RestStatus.FORBIDDEN));
            return false;
        }
        return true;
    }

    private static boolean isLocked() {
        try {
            return PluginSettings.getInstance().isSensitiveConfigLocked();
        } catch (IllegalStateException e) {
            // Settings not initialized yet (no request can reach a protected action before then).
            return false;
        }
    }
}
