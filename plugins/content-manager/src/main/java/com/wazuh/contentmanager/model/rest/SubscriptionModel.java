package com.wazuh.contentmanager.model.rest;

/**
 * Singleton subscription model for managing CTI subscription data.
 * Only one subscription can exist at a time in the system.
 * Thread-safe implementation using synchronized methods.
 */
public class SubscriptionModel {
    private static volatile SubscriptionModel instance = null;

    private String deviceCode;
    private String clientId;
    private int expiresIn;
    private int interval;

    private SubscriptionModel() {}

    private SubscriptionModel(String deviceCode, String clientId, int expiresIn, int interval) {
        this.deviceCode = deviceCode;
        this.clientId = clientId;
        this.expiresIn = expiresIn;
        this.interval = interval;
    }

    /**
     * Creates or updates the singleton subscription instance.
     * If an instance already exists, it will be replaced with the new values.
     *
     * @param deviceCode The device code for the subscription
     * @param clientId The client ID for the subscription
     * @param expiresIn Expiration time in seconds
     * @param interval Polling interval in seconds
     * @return The created or updated subscription instance
     */
    public static synchronized SubscriptionModel createOrUpdate(String deviceCode, String clientId, int expiresIn, int interval) {
        instance = new SubscriptionModel(deviceCode, clientId, expiresIn, interval);
        return instance;
    }

    /**
     * Retrieves the current subscription instance.
     *
     * @return The current subscription instance, or null if no subscription exists
     */
    public static synchronized SubscriptionModel getInstance() {
        if (instance == null) {
            throw new IllegalStateException("SubscriptionModel have not been initialized.");
        }
        return instance;
    }

    /**
     * Deletes the current subscription instance.
     */
    public static synchronized void deleteInstance() {
        instance = null;
    }

    // Getters
    public String getDeviceCode() {
        return deviceCode;
    }

    public String getClientId() {
        return clientId;
    }

    public int getExpiresIn() {
        return expiresIn;
    }

    public int getInterval() {
        return interval;
    }

}
