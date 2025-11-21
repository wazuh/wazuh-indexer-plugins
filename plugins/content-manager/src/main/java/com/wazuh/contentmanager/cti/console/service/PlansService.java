package com.wazuh.contentmanager.cti.console.service;

import com.wazuh.contentmanager.cti.console.model.Plan;

import java.util.List;

public interface PlansService {

    List<Plan> getPlans(String permanentToken);
}
