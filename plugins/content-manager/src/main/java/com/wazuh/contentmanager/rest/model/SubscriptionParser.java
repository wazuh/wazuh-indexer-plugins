package com.wazuh.contentmanager.rest.model;


import com.wazuh.contentmanager.cti.console.model.Subscription;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SubscriptionParser extends Subscription {

    public static Subscription parse(XContentParser parser) throws IOException {
        String deviceCode = null;
        String clientId = null;
        Integer expiresIn = null;
        Integer interval = null;

        while (!parser.isClosed()) {
            XContentParser.Token token = parser.nextToken();

            if (token.isValue()) {
                String fieldName = parser.currentName();
                switch (fieldName) {
                    case Subscription.DEVICE_CODE -> deviceCode = parser.text();
                    case Subscription.CLIENT_ID -> clientId = parser.text();
                    case Subscription.EXPIRES_IN -> expiresIn = parser.intValue();
                    case Subscription.INTERVAL -> interval = parser.intValue();
                    default -> { }
                }
            }
        }

        // Check for missing params
        List<String> missingParams = new ArrayList<>();
        if (deviceCode == null) {
            missingParams.add(Subscription.DEVICE_CODE);
        }
        if (clientId == null) {
            missingParams.add(Subscription.CLIENT_ID);
        }
        if (expiresIn == null) {
            missingParams.add(Subscription.EXPIRES_IN);
        }
        if (interval == null) {
            missingParams.add(Subscription.INTERVAL);
        }

        // Throw error if required params are missing.
        if (!missingParams.isEmpty()) {
            throw new IllegalArgumentException("Missing required parameters: " + missingParams);
        }

        // Return new instance of Subscription
        return new Subscription(deviceCode, clientId, expiresIn, interval);

        // Create or update the subscription via the service
//        service.setSubscription(deviceCode, clientId, expiresIn, interval);
    }

}
