package com.wazuh.contentmanager.rest.model;


import com.wazuh.contentmanager.cti.console.model.Subscription;
import org.opensearch.core.xcontent.XContentParser;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

/**
 * Utility parser that reads a Subscription object from an XContent stream. 
 * This class extends {@link com.wazuh.contentmanager.cti.console.model.Subscription}
 * solely to expose a convenient static parser and does not add additional
 * instance state or behavior.
 */
public class SubscriptionParser extends Subscription {

    /**
     * Parse a {@link com.wazuh.contentmanager.cti.console.model.Subscription} from the provided
     * {@link org.opensearch.core.xcontent.XContentParser}.
     *
     * The parser expects the following top-level fields to be present in the
     * XContent object: {@code device_code}, {@code client_id}, {@code expires_in}
     * and {@code interval}. If any required field is missing an
     * {@link IllegalArgumentException} is thrown.
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
        while ((token = parser.nextToken()) != null) {
            if (token == XContentParser.Token.FIELD_NAME) {
                String fieldName = parser.currentName();
                parser.nextToken();
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
    }

}
