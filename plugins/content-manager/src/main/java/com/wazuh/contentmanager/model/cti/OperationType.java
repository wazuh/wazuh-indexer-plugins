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
package com.wazuh.contentmanager.model.cti;

/**
 * This enumeration represents the types of supported operations of the Content Manager plugin from
 * the JSON Patch operations set:
 *
 * <pre>
 *   - test    --> unsupported
 *   - remove  --> {@link OperationType#DELETE}
 *   - add     --> {@link OperationType#CREATE}
 *   - replace --> {@link OperationType#UPDATE}
 *   - move    --> unsupported
 *   - copy    --> unsupported
 * </pre>
 */
public enum OperationType {
    CREATE,
    UPDATE,
    DELETE
}
