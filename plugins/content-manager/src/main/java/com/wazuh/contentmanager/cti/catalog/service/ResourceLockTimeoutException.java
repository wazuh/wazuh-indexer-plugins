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
package com.wazuh.contentmanager.cti.catalog.service;

import java.io.IOException;

/**
 * Signals that {@link ResourceLockService#acquire} could not obtain the lock after its configured
 * retry budget because another caller kept holding/refreshing it — genuine contention, not a server
 * fault. Callers should map this specifically to {@code 429 Too Many Requests}; any other failure
 * from {@code acquire} (index-creation failure, a non-conflict write error) is a different,
 * unrelated fault and must not be classified this way.
 */
public class ResourceLockTimeoutException extends IOException {

    /**
     * @param message the timeout detail, identifying the resource type and space.
     */
    public ResourceLockTimeoutException(String message) {
        super(message);
    }
}
