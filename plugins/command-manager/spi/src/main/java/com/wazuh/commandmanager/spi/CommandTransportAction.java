package com.wazuh.commandmanager.spi;

import org.opensearch.action.ActionType;
import org.opensearch.action.support.master.AcknowledgedResponse;

// Shared constant
public class CommandTransportAction {
    public static final ActionType<AcknowledgedResponse> ACTION_TYPE =
        new ActionType<>("internal:command/execute", AcknowledgedResponse::new);

}
