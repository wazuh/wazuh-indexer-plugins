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
package com.wazuh.contentmanager.cti.catalog.service;

import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

/** Service interface for managing and retrieving CTI Catalog consumer states. */
public interface ConsumerService {

    /**
     * Retrieves the current local consumer state.
     *
     * @return The {@link LocalConsumer} object representing the local state.
     */
    LocalConsumer getLocalConsumer();

    /**
     * Retrieves the current remote consumer state.
     *
     * @return The {@link RemoteConsumer} object representing the remote state.
     */
    RemoteConsumer getRemoteConsumer();
}
