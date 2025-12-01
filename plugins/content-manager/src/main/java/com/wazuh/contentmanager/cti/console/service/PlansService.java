package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;

import java.util.List;

/**
 * Service interface definition for managing CTI Plans.
 */
public interface PlansService extends ClosableHttpClient {

    /**
     * Retrieves the list of available CTI plans authorized by the provided token.
     *
     * @param token the authentication {@link Token} required to validate the request.
     * @return a {@link List} of {@link Plan} objects available to the user. Returns an empty list if no plans are found.
     */
    List<Plan> getPlans(Token token);
}
