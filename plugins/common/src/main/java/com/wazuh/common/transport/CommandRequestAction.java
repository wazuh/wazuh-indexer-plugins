package com.wazuh.common.transport;

import org.opensearch.action.ActionType;

public class CommandRequestAction extends ActionType<CommandResponse> {
    public static final String NAME = "cluster:admin/wazuh/command/send";
    public static final CommandRequestAction INSTANCE = new CommandRequestAction();

    private CommandRequestAction() {
        super(NAME, CommandResponse::new);
    }
}
