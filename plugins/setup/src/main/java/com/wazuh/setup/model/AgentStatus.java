package com.wazuh.setup.model;

import java.util.Locale;

/** Set of agent's statuses. */
public enum AgentStatus {
    /** Agent is login on this API. */
    ACTIVE("active"),

    /** Agent was enrrolled but it never has logged. */
    NEVER_CONNECTED("never_connected"),

    /** Agent has been loged successfully but a certain amount of time has passed since the agent's last login.*/
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
