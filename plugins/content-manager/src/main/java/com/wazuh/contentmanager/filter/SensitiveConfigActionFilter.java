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

import com.wazuh.contentmanager.action.TriggerUpdateAction;
import com.wazuh.contentmanager.action.UpdatePolicyAction;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Action filter that blocks modification of sensitive Content Manager configuration when the
 * corresponding per-endpoint setting is disabled:
 *
 * <ul>
 *   <li>{@code plugins.content_manager.catalog.update_on_demand} gates {@link TriggerUpdateAction}
 *       (content update trigger).
 *   <li>{@code plugins.content_manager.catalog.policy_update.enabled} gates {@link
 *       UpdatePolicyAction} (policy updates).
 * </ul>
 *
 * <p>When a protected action's setting is {@code false}, the action fails with {@code 403
 * FORBIDDEN} for every caller, regardless of role. This is decoupled from the transport-action
 * implementations: it matches them by action name (the same names the security plugin enforces as
 * cluster permissions), so it works regardless of which class owns the action.
 */
public class SensitiveConfigActionFilter extends ActionFilter.Simple {

    @Override
    public int order() {
        return 0;
    }

    @Override
    protected boolean apply(String action, ActionRequest request, ActionListener<?> listener) {
        String message = disabledMessage(action);
        if (message != null) {
            listener.onFailure(new OpenSearchStatusException(message, RestStatus.FORBIDDEN));
            return false;
        }
        return true;
    }

    /**
     * Returns the {@code 403} message when the given action is disabled by its setting, or {@code
     * null} when the action is allowed (not protected, or its setting is enabled).
     *
     * @param action the transport-action name being executed.
     * @return the forbidden message, or {@code null} when the action may proceed.
     */
    private static String disabledMessage(String action) {
        try {
            PluginSettings settings = PluginSettings.getInstance();
            if (UpdatePolicyAction.NAME.equals(action) && !settings.isPolicyUpdateEnabled()) {
                return Constants.E_403_POLICY_UPDATE_DISABLED;
            }
            if (TriggerUpdateAction.NAME.equals(action) && !settings.isUpdateOnDemandEnabled()) {
                return Constants.E_403_UPDATE_ON_DEMAND_DISABLED;
            }
            return null;
        } catch (IllegalStateException e) {
            // Settings not initialized yet (no request can reach a protected action before then).
            return null;
        }
    }
}
