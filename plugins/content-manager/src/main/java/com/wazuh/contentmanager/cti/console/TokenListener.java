/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.console;

import java.util.EventListener;

import com.wazuh.contentmanager.cti.console.model.Token;

/** Listener interface for receiving notifications about Token changes. */
public interface TokenListener extends EventListener {

    /**
     * Invoked when the authentication token has changed (e.g., refreshed or initially acquired).
     *
     * @param token The new {@link Token}.
     */
    void onTokenChanged(Token token);
}
