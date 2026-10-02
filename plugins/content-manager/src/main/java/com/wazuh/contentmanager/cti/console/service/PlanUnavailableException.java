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
 * Signals that the environment's plan could not be obtained from the CTI Console for a reason that
 * says nothing about the access token: a network error, a timeout, a status other than {@code 200}
 * and {@code 401} (such as {@code 429} or a {@code 5xx}), or a response that cannot be parsed or
 * lists no plan. Callers must treat the registration as unchanged: keep the stored token and the
 * current content source, and retry later. A rejected token is a {@link TokenRejectedException}
 * instead.
 */
public class PlanUnavailableException extends IOException {

    /**
     * @param message the failure detail.
     */
    public PlanUnavailableException(String message) {
        super(message);
    }

    /**
     * @param message the failure detail.
     * @param cause the underlying failure.
     */
    public PlanUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
