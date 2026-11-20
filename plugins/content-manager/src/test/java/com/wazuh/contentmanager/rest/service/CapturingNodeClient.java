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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.action.ActionRequest;
import org.opensearch.action.ActionType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.action.ActionResponse;
import org.opensearch.test.client.NoOpNodeClient;

/**
 * Node client for REST handler tests: captures the dispatched request and replies with a
 * caller-supplied response, or with nothing when {@link #response} is null.
 *
 * @param <R> the request type the handler under test dispatches
 */
class CapturingNodeClient<R extends ActionRequest> extends NoOpNodeClient {
    R captured;
    ActionResponse response;

    CapturingNodeClient(String testName) {
        super(testName);
    }

    @Override
    @SuppressWarnings("unchecked")
    public <Request extends ActionRequest, Response extends ActionResponse> void doExecute(
            ActionType<Response> action, Request request, ActionListener<Response> listener) {
        this.captured = (R) request;
        if (this.response != null) {
            listener.onResponse((Response) this.response);
        }
    }
}
