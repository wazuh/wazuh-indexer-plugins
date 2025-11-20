package com.wazuh.contentmanager.model.rest;

/**
 * Subscription model for managing CTI subscription data.
 */
public class SubscriptionModel {
    private String deviceCode;
    private String clientId;
    private int expiresIn;
    private int interval;

    public SubscriptionModel(String deviceCode, String clientId, int expiresIn, int interval) {
        this.deviceCode = deviceCode;
        this.clientId = clientId;
        this.expiresIn = expiresIn;
        this.interval = interval;
    }

}
