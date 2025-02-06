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
package com.wazuh.commandmanager.model;

import java.util.Locale;

/** Set of commands' statuses. */
public enum Status {
/** Command has been received and indexed, but not yet processed. */
PENDING,
/** Command has been sent to the target. */
SENT,
/**
* Command has been executed successfully. Set by external actors, by directly updating the
* document.
*/
SUCCESS,
/**
* Command could not be sent to the target or the execution failed. Set by the plugin or by
* external actors, respectively.
*/
FAILURE;

@Override
public String toString() {
	return name().toLowerCase(Locale.ROOT);
}
}
