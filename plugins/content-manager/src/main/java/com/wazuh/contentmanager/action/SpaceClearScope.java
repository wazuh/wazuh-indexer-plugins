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
package com.wazuh.contentmanager.action;

/**
 * The portion of a space a {@link DeleteSpaceRequest} targets.
 *
 * <p>The enum ordinal is serialized on the wire by {@code DeleteSpaceRequest}, so new values must
 * be appended, never reordered.
 */
public enum SpaceClearScope {
    /** The whole space: the existing reset (delete every resource and re-initialize the space). */
    FULL,
    /** Only the normalization resources: decoders, kvdbs, filters, and the policy root decoder. */
    NORMALIZATION,
    /** Only the detection resources: rules. */
    DETECTION
}
