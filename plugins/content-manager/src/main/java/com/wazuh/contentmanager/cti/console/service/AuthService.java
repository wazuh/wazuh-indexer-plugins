package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.TokenListener;
import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.model.Subscription;

public interface AuthService extends ClosableHttpClient {

    Token getToken(Subscription s);
    Token getResourceToken(Token t, String resource);

    void addListener(TokenListener listener);
}
