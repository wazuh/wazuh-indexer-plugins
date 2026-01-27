/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.engine.utils;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.transport.client.Client;

import java.io.IOException;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.rest.model.Policy;

public class PolicyHandler {
    private static final Logger log = LogManager.getLogger(PolicyHandler.class);

    public static Policy getPolicyFromJson(String jsonString) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        Policy policy;
        try {
            policy = mapper.readValue(jsonString, Policy.class);
            return policy;
        } catch (IOException e) {
            log.debug("Invalid Policy JSON content: " + e.getMessage());
            return null;
        }
    }

    public static Policy getPolicyFromJson(BytesReference jsonBytes) throws Exception {
        return getPolicyFromJson(jsonBytes.utf8ToString());
    }

    public static String policyToJson(Policy policy) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        try {
            return mapper.writeValueAsString(policy);
        } catch (IOException e) {
            log.debug("Error converting Policy to JSON: " + e.getMessage());
            return null;
        }
    }

    public static Policy searchPolicyBySpace(String space, Client client) {
        ContentIndex index =
                new ContentIndex(client, "TEST", "/mappings/cti-policies-mappings.json", ".cti-policies");
        Resource resource = index.searchByKeyValue("space", space);
        if (resource == null) {
            return null;
        }
        Policy policy;
        try {
            policy = getPolicyFromJson(resource.getDocument().toString());
            return policy;
        } catch (Exception ex) {
            log.debug("Error parsing Policy from search result: " + ex.getMessage());
            return null;
        }
    }

    public static void createDefaultPolicy(Client client) {
        // TODO: Implement the logic to create a default policy in the draft space.
        indexPolicy(new Policy(), "draft", client);
    }

    public static void indexPolicy(Policy policy, String space, Client client) {
        // TODO: Implement the logic to create the given policy in the appropriate space.
    }
}
