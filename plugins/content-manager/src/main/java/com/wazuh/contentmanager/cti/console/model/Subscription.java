/*
 * Copyright (C) 2024, Wazuh Inc.
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
package com.wazuh.contentmanager.cti.console.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/** Subscription model for managing CTI subscription data. */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Subscription {
    public static final String DEVICE_CODE = "device_code";
    public static final String CLIENT_ID = "client_id";
    public static final String EXPIRES_IN = "expires_in";
    public static final String INTERVAL = "interval";

    @JsonProperty(DEVICE_CODE)
    private String deviceCode;

    @JsonProperty(CLIENT_ID)
    private String clientId;

    @JsonProperty(EXPIRES_IN)
    private int expiresIn;

    @JsonProperty(INTERVAL)
    private int interval;

    /** Default constructor for frameworks that require a no-arg constructor */
    public Subscription() {}

    /**
     * Constructs a Subscription with all fields set.
     *
     * @param deviceCode the device code returned by the CTI provider
     * @param clientId the client identifier associated with the subscription
     * @param expiresIn seconds until the device code expires
     * @param interval polling interval in seconds to check subscription status
     */
    public Subscription(String deviceCode, String clientId, int expiresIn, int interval) {
        this.setDeviceCode(deviceCode);
        this.setClientId(clientId);
        this.setExpiresIn(expiresIn);
        this.setInterval(interval);
    }

    /**
     * Parse a {@link Subscription} from the provided {@link
     * org.opensearch.core.xcontent.XContentParser}.
     *
     * <p>The parser expects the following top-level fields to be present in the XContent object:
     * {@code device_code}, {@code client_id}, {@code expires_in} and {@code interval}. If any
     * required field is missing an {@link IllegalArgumentException} is thrown.
     *
     * @param parser the XContent parser positioned at the start of an object
     * @return a new {@code Subscription} instance populated with parsed values
     * @throws IOException if an I/O error occurs while reading from the parser
     * @throws IllegalArgumentException if required fields are missing
     */
    public static Subscription parse(XContentParser parser) throws IOException {
        String deviceCode = null;
        String clientId = null;
        Integer expiresIn = null;
        Integer interval = null;

        XContentParser.Token token;
        // Move to the next token, which should be the start of the object's fields
        while ((token = parser.nextToken()) != null) {
            if (token == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken(); // Move to the value token
                switch (fieldName) {
                    case DEVICE_CODE -> deviceCode = parser.text();
                    case CLIENT_ID -> clientId = parser.text();
                    case EXPIRES_IN -> expiresIn = parser.intValue();
                    case INTERVAL -> interval = parser.intValue();
                    default -> {
                        /* ignore unknown fields */
                    }
                }
            } else if (token == XContentParser.Token.END_OBJECT) {
                // Break out once the object is fully parsed
                break;
            }
        }

        // Check for missing params
        List<String> missingParams = new ArrayList<>();
        if (deviceCode == null) {
            missingParams.add(DEVICE_CODE);
        }
        if (clientId == null) {
            missingParams.add(CLIENT_ID);
        }
        if (expiresIn == null) {
            missingParams.add(EXPIRES_IN);
        }
        if (interval == null) {
            missingParams.add(INTERVAL);
        }

        // Throw error if required params are missing.
        if (!missingParams.isEmpty()) {
            throw new IllegalArgumentException("Missing required parameters: " + missingParams);
        }

        // Return new instance of Subscription
        return new Subscription(deviceCode, clientId, expiresIn, interval);
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
        return "{"
                + "deviceCode='"
                + this.deviceCode
                + '\''
                + ", clientId='"
                + this.clientId
                + '\''
                + ", expiresIn="
                + this.expiresIn
                + ", interval="
                + this.interval
                + '}';
    }
}
