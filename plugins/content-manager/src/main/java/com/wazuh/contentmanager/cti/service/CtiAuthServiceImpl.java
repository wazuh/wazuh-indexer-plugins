package com.wazuh.contentmanager.cti.service;

import com.wazuh.contentmanager.cti.client.CtiApiClient;
import com.wazuh.contentmanager.cti.model.Token;

public class CtiAuthServiceImpl implements CtiAuthService {

    CtiApiClient client = new CtiApiClient();

    /**
     * @param clientId
     * @param deviceCode
     * @return
     */
    @Override
    public Token getToken(String clientId, String deviceCode) {
        // Perform request
        this.client.getToken(clientId, deviceCode);

        // Parse response
        Token.parse()

        //
        return null;
    }

    /**
     * @param permanentToken
     * @param resource
     * @return
     */
    @Override
    public Token getResourceToken(String permanentToken, String resource) {
        return null;
    }
}
