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
 * Signals that the CTI Console rejected the stored access token: {@code GET
 * /platform/environments/me} answered {@code 401 Unauthorized}, so the token is expired, revoked or
 * invalid. This is the only plan-lookup failure that says anything about the token, and the only
 * one after which the stored credentials may be cleared. Every other failure is a {@link
 * PlanUnavailableException}.
 */
public class TokenRejectedException extends IOException {

    /**
     * @param message the rejection detail.
     */
    public TokenRejectedException(String message) {
        super(message);
    }
}
