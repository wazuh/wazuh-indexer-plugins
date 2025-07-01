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
package com.wazuh.setup.index;

/**
 * Public interface for index creation. Any class creating indices must implement this interface.
 */
public interface IndexInitializer {
    /**
     * Creates an index.
     *
     * @param index Name of the index to create.
     * @return true if it was correctly created, false otherwise.
     */
    boolean createIndex(String index);

    /**
     * Creates an index template.
     *
     * @param template name of the index template to create.
     * @return true if it was correctly created, false otherwise.
     */
    boolean createTemplate(String template);
}
