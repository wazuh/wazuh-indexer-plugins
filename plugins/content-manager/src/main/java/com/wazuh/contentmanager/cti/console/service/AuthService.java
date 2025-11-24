package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.TokenListener;
import com.wazuh.contentmanager.cti.console.model.Token;

public interface AuthService {

    Token getToken(String clientId, String deviceCode);
    Token getResourceToken(String permanentToken, String resource);

    void addListener(TokenListener listener);
}
