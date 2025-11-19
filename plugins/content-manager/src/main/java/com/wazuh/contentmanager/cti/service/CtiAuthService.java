package com.wazuh.contentmanager.cti.service;

import com.wazuh.contentmanager.cti.model.Token;

public interface CtiAuthService {

    Token getToken(String clientId, String deviceCode);
    Token getResourceToken(String permanentToken, String resource);

}
