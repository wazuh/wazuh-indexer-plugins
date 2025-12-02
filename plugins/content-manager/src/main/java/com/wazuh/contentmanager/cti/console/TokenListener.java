package com.wazuh.contentmanager.cti.console;

import com.wazuh.contentmanager.cti.console.model.Token;

import java.util.EventListener;

/**
 * Listener interface for receiving notifications about Token changes.
 */
public interface TokenListener extends EventListener {

    /**
     * Invoked when the authentication token has changed (e.g., refreshed or initially acquired).
     *
     * @param token The new {@link Token}.
     */
    void onTokenChanged(Token token);
}
