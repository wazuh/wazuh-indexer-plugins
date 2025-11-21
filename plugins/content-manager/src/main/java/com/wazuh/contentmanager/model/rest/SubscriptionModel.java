package com.wazuh.contentmanager.model.rest;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Subscription model for managing CTI subscription data.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class SubscriptionModel {
    @JsonProperty("device_code")
    private String deviceCode;
    @JsonProperty("client_id")
    private String clientId;
    @JsonProperty("expires_in")
    private int expiresIn;
    @JsonProperty("interval")
    private int interval;

    public SubscriptionModel() { }

    public SubscriptionModel(String deviceCode, String clientId, int expiresIn, int interval) {
        this.deviceCode = deviceCode;
        this.clientId = clientId;
        this.expiresIn = expiresIn;
        this.interval = interval;
    }

    public String getDeviceCode() {
        return this.deviceCode;
    }

    public void setDeviceCode(String deviceCode) {
        this.deviceCode = deviceCode;
    }

    public String getClientId() {
        return this.clientId;
    }

    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    public int getExpiresIn() {
        return this.expiresIn;
    }

    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }

    public int getInterval() {
        return this.interval;
    }

    public void setInterval(int interval) {
        this.interval = interval;
    }

    @Override
    public String toString() {
        return "{" +
            "deviceCode='" + deviceCode + '\'' +
            ", clientId='" + clientId + '\'' +
            ", expiresIn=" + expiresIn +
            ", interval=" + interval +
            '}';
    }
}
