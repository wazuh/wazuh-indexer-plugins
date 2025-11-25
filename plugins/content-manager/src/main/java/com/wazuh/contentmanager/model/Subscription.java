package com.wazuh.contentmanager.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Subscription model for managing CTI subscription data.
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Subscription {
    @JsonProperty("device_code")
    private String deviceCode;
    @JsonProperty("client_id")
    private String clientId;
    @JsonProperty("expires_in")
    private int expiresIn;
    @JsonProperty("interval")
    private int interval;

    /**
     * Default constructor for frameworks that require a no-arg constructor
     */
    public Subscription() { }

    /**
     * Constructs a Subscription with all fields set.
     *
     * @param deviceCode the device code returned by the CTI provider
     * @param clientId   the client identifier associated with the subscription
     * @param expiresIn  seconds until the device code expires
     * @param interval   polling interval in seconds to check subscription status
     */
    public Subscription(String deviceCode, String clientId, int expiresIn, int interval) {
        this.deviceCode = deviceCode;
        this.clientId = clientId;
        this.expiresIn = expiresIn;
        this.interval = interval;
    }

    /**
     * Returns the device code for the subscription.
     *
     * @return the device code string, may be null
     */
    public String getDeviceCode() {
        return this.deviceCode;
    }

    /**
     * Sets the device code for the subscription.
     *
     * @param deviceCode the device code returned by the CTI provider
     */
    public void setDeviceCode(String deviceCode) {
        this.deviceCode = deviceCode;
    }

    /**
     * Returns the client identifier associated with this subscription.
     *
     * @return the client id string, may be null
     */
    public String getClientId() {
        return this.clientId;
    }

    /**
     * Sets the client identifier for this subscription.
     *
     * @param clientId the client id to set
     */
    public void setClientId(String clientId) {
        this.clientId = clientId;
    }

    /**
     * Returns the lifetime in seconds until the device code expires.
     *
     * @return number of seconds until expiration
     */
    public int getExpiresIn() {
        return this.expiresIn;
    }

    /**
     * Sets the expiration lifetime in seconds for the device code.
     *
     * @param expiresIn the expiration time in seconds
     */
    public void setExpiresIn(int expiresIn) {
        this.expiresIn = expiresIn;
    }

    /**
     * Returns the polling interval (in seconds) to check the subscription status.
     *
     * @return polling interval in seconds
     */
    public int getInterval() {
        return this.interval;
    }

    /**
     * Sets the polling interval in seconds for subscription status checks.
     *
     * @param interval polling interval in seconds
     */
    public void setInterval(int interval) {
        this.interval = interval;
    }

    /**
     * Returns a compact string representation of this Subscription.
     *
     * @return string representation containing deviceCode, clientId, expiresIn and interval
     */
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
