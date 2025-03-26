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
package com.wazuh.setup.model;

/** Set of agent's statuses. */
public enum AgentStatus {
    /** Agent is login on this API. */
    ACTIVE("active"),

    /** Agent was enrrolled but it never has logged. */
    NEVER_CONNECTED("never_connected"),

    /**
     * Agent has been loged successfully but a certain amount of time has passed since the agent's
     * last login.
     */
    DISCONNECTED("disconnected");

    private final String status;

    AgentStatus(String status) {
        this.status = status;
    }

    @Override
    public String toString() {
        return status;
    }
}
