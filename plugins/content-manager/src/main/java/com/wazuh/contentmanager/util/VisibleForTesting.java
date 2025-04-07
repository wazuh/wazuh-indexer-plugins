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

/**
 * Annotation to indicate that a method, field, or class is more visible than necessary strictly for
 * testing purposes.
 *
 * <p>This annotation serves as a documentation aid to highlight that the increased visibility of an
 * otherwise private or package-private member is intentional for unit testing.
 *
 * <p>Usage example:
 *
 * <pre>{@code
 * @VisibleForTesting
 * void someTestableMethod() {
 *     // Implementation
 * }
 * }</pre>
 */
public @interface VisibleForTesting {}
