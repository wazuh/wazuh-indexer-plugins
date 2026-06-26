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
package com.wazuh.setup.action;

import org.opensearch.action.ActionType;

/**
 * Transport action for persisting Wazuh settings. Its {@link #NAME} doubles as the cluster
 * permission enforced by the security plugin, restricting access to authorized roles.
 */
public class PutSettingsAction extends ActionType<PutSettingsResponse> {
    public static final String NAME = "plugin:setup/settings/write";
    public static final PutSettingsAction INSTANCE = new PutSettingsAction();

    public PutSettingsAction() {
        super(NAME, PutSettingsResponse::new);
    }
}
