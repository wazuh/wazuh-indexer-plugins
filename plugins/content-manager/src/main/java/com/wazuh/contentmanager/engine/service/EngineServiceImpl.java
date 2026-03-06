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
package com.wazuh.contentmanager.engine.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.wazuh.contentmanager.engine.client.EngineSocketClient;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.POST;

public class EngineServiceImpl implements EngineService {
    public static final String LOGTEST = "logtest";
    static final String VALIDATE = "/content/validate/resource";
    static final String PROMOTE = "/content/validate/policy";

    private final EngineSocketClient socket;
    private final ObjectMapper mapper;

    /** Default constructor. */
    public EngineServiceImpl() {
        this.socket = new EngineSocketClient();
        this.mapper = new ObjectMapper();
    }

    /**
     * Parametrized constructor
     *
     * @param socket instance of {@link EngineSocketClient}
     */
    public EngineServiceImpl(EngineSocketClient socket) {
        this.socket = socket;
        this.mapper = new ObjectMapper();
    }

    @Override
    public RestResponse logtest(JsonNode log) {
        return this.socket.sendRequest(LOGTEST, POST.name(), log);
    }

    @Override
    public RestResponse validate(JsonNode resource) {
        return this.socket.sendRequest(VALIDATE, POST.name(), resource);
    }

    @Override
    public RestResponse promote(JsonNode policy) {
        return this.socket.sendRequest(PROMOTE, POST.name(), policy);
    }

    @Override
    public RestResponse validateResource(String type, JsonNode resource) {
        ObjectNode payload = this.mapper.createObjectNode();
        payload.put(Constants.KEY_TYPE, type);
        payload.set(Constants.KEY_RESOURCE, resource);
        return this.validate(payload);
    }
}
