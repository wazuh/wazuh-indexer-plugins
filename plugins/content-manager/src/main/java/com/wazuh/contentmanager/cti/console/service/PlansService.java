package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.client.ClosableHttpClient;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Token;

import java.util.List;

public interface PlansService extends ClosableHttpClient {

    List<Plan> getPlans(Token token);
}
