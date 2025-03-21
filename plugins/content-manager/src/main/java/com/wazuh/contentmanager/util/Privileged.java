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
package com.wazuh.contentmanager.util;

import java.security.AccessController;
import java.security.PrivilegedAction;

/** Privileged utility class for executing privileged HTTP requests. */
public class Privileged {

    /**
     * Executes an HTTP request with elevated privileges.
     *
     * @param <T> A privileged action that performs the HTTP request.
     * @return The return value resulting from the request execution.
     */
    public static <T> T doPrivilegedRequest(java.security.PrivilegedAction<T> request) {
        return AccessController.doPrivileged(request);
    }
}
