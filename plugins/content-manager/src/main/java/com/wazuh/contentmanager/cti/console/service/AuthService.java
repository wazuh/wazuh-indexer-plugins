package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.TokenListener;
import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;
import com.wazuh.contentmanager.cti.console.model.Token;

public interface AuthService extends ClosableHttpClient {

    Token getToken(String clientId, String deviceCode);
    Token getResourceToken(Token permanentToken, String resource);

    void addListener(TokenListener listener);
}
