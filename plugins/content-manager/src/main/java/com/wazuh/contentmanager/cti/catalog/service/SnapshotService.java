/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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

import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

/**
 * Service interface for managing CTI snapshots. Defines the contract for initializing consumers
 * from remote snapshots.
 */
public interface SnapshotService {

    /**
     * Initializes a consumer by processing its associated remote snapshot.
     *
     * @param consumer The remote consumer containing the snapshot link and offset information.
     * @return true if the snapshot was downloaded and initialized successfully; false otherwise.
     */
    boolean initialize(RemoteConsumer consumer);

    /**
     * Initializes a consumer from a pre-packaged local snapshot zip file.
     *
     * @param localZip Path to the local snapshot zip file.
     * @return true if the local snapshot was processed and initialized successfully; false otherwise.
     */
    boolean initializeFromLocal(java.nio.file.Path localZip);
}
