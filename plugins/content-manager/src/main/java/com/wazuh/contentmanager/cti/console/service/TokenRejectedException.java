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
package com.wazuh.contentmanager.cti.console.service;

import java.io.IOException;

/**
 * Signals that the CTI Console rejected the stored access token, so it is expired, revoked or
 * invalid: {@code 401} from the plan lookup, or {@code 401} or {@code 400 unauthorized_client} from
 * the resource-token exchange. This is the only CTI Console failure that says anything about the
 * token, and the only one after which the token may be cleared. Every other failure is a {@link
 * CtiConsoleUnavailableException}.
 */
public class TokenRejectedException extends IOException {

    /**
     * @param message the rejection detail.
     */
    public TokenRejectedException(String message) {
        super(message);
    }
}
