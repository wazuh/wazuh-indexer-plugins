package com.wazuh.contentmanager.cti.console;

import com.wazuh.contentmanager.cti.console.model.Token;

import java.util.EventListener;

public interface TokenListener extends EventListener {

    void onTokenChanged(Token t);
}
