package com.wazuh.contentmanager.cti.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.wazuh.contentmanager.cti.client.CtiApiClient;
import com.wazuh.contentmanager.cti.model.Token;
import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.IOException;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeoutException;


public class CtiAuthServiceImpl implements CtiAuthService {

    private static final Logger log = LogManager.getLogger(CtiAuthServiceImpl.class);

    private final CtiApiClient client;
    private final ObjectMapper mapper;

    public CtiAuthServiceImpl() {
        this.client = new CtiApiClient();
        this.mapper = new ObjectMapper();
    }

    /**
     * @param clientId
     * @param deviceCode
     * @return
     */
    @Override
    public Token getToken(String clientId, String deviceCode) {
        try {
            // Perform request
            SimpleHttpResponse response = this.client.getToken(clientId, deviceCode);

            if (response.getCode() == 200) {
                // Parse response
                return this.mapper.readValue(response.getBodyText(), Token.class);
            } else {
                log.warn("Operation to fetch a permanent token failed: { \"status_code\": {}, \"message\": {}", response.getCode(), response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain permanent token from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse permanent token: {}", e.getMessage());
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
        try {
            // Perform request
            SimpleHttpResponse response = this.client.getResourceToken(permanentToken, resource);
            if (response.getCode() == 200) {
                // Parse response
                return this.mapper.readValue(response.getBodyText(), Token.class);
            } else {
                log.warn("Operation to fetch a resource token failed: { \"status_code\": {}, \"message\": {}", response.getCode(), response.getBodyText());
            }
        } catch (ExecutionException | InterruptedException | TimeoutException e) {
            log.error("Couldn't obtain resource token from CTI: {}", e.getMessage());
        } catch (IOException e) {
            log.error("Failed to parse resource token: {}", e.getMessage());
        }
        return null;
    }
}
