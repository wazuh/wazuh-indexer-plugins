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
 * Class to represent a Stateful index. Stateful indices represent the most recent information of a
 * subject (active vulnerabilities, installed packages, open ports, ...). These indices are
 * different of Stream indices as they do not contain timestamps. The information is not based on
 * time, as they always represent the most recent state.
 */
public class StateIndex extends WazuhIndex {

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    public StateIndex(String index, String template) {
        super(index, template);
    }
}
