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

import org.opensearch.core.action.ActionListener;

import com.wazuh.contentmanager.rest.model.RestResponse;

public interface EngineService {

    RestResponse logtest(JsonNode log);

    RestResponse validate(JsonNode resource);

    /**
     * Sends a policy to the Engine to validate and, for a tester space, load. Sends it at once,
     * without waiting for other promotes: use {@link #promoteAsync} to load a space, so that two
     * loads never overlap in the Engine.
     *
     * @param policy the Engine payload to promote.
     * @return the Engine's response.
     */
    RestResponse promote(JsonNode policy);

    /**
     * Asynchronous variant of {@link #promote(JsonNode)} that offloads the blocking socket I/O to a
     * background thread. Use this from transport-thread callbacks where blocking is not permitted.
     * Implementations send the promotes of a node to the Engine one at a time.
     *
     * @param policy the Engine payload to promote.
     * @param listener receives the {@link RestResponse} on success, or the exception on failure.
     */
    void promoteAsync(JsonNode policy, ActionListener<RestResponse> listener);

    RestResponse validateResource(String type, JsonNode resource);

    /**
     * Notifies the Engine to load IOC content from the given file path.
     *
     * @param filePath The absolute path to the NDJSON file containing IOC data.
     * @param hash The combined SHA-256 hash of all IOC type hashes.
     * @return A {@link RestResponse} with the Engine's response.
     */
    RestResponse updateIoc(String filePath, String hash);

    /**
     * Queries the Engine for the current IOC processing state.
     *
     * @return A {@link RestResponse} whose message contains the JSON state (e.g., {@code
     *     {"hash":"...","updating":false}}).
     */
    RestResponse getIocState();
}
