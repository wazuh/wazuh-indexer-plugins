package com.wazuh.contentmanager.cti.service;

import com.wazuh.contentmanager.cti.client.CtiApiClient;
import com.wazuh.contentmanager.cti.model.Token;
import com.wazuh.contentmanager.utils.XContentUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;


public class CtiAuthServiceImpl implements CtiAuthService {

    private static final Logger log = LogManager.getLogger(CtiAuthServiceImpl.class);

    CtiApiClient client = new CtiApiClient();

    /**
     * @param clientId
     * @param deviceCode
     * @return
     */
    @Override
    public Token getToken(String clientId, String deviceCode) {
        try {
            // Perform request
            String response = this.client.getToken(clientId, deviceCode);
            log.info("Brrrr token" + response);

            // Parse response
            XContentParser parser = XContentUtils
                .createJSONParser(response.getBytes(StandardCharsets.UTF_8));

            return Token.parse(parser);
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain token from CTI");
        } catch (IOException e) {
            log.error("Failed to parse token");
        }
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
