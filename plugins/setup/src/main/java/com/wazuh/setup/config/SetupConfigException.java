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
package com.wazuh.setup.config;

/**
 * Thrown when the configuration of the plugin cannot be used. The message names the key or the file
 * at fault.
 */
public class SetupConfigException extends RuntimeException {

    /**
     * Constructor.
     *
     * @param message what is wrong, naming the key or the file.
     */
    public SetupConfigException(String message) {
        super(message);
    }

    /**
     * Constructor.
     *
     * @param message what is wrong, naming the key or the file.
     * @param cause error raised while reading or validating the configuration.
     */
    public SetupConfigException(String message, Throwable cause) {
        super(message, cause);
    }
}
