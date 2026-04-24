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

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.env.Environment;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.BytesRestResponse;
import org.opensearch.rest.NamedRoute;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.node.NodeClient;

import java.io.IOException;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.List;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.model.Release;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.model.VersionCheckResponse;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.opensearch.rest.RestRequest.Method.GET;

/**
 * GET /_plugins/_content_manager/version/check
 *
 * <p>Returns available Wazuh version updates by querying the CTI API. The response includes the
 * latest available major, minor, and patch updates.
 *
 * <p>Possible HTTP responses:
 *
 * <ul>
 *   <li>200 OK: Updates retrieved successfully
 *   <li>500 Internal Server Error: Unable to determine version or unexpected error
 *   <li>502 Bad Gateway: CTI API returned an error
 * </ul>
 */
public class RestGetVersionCheckAction extends BaseRestHandler {
    private static final Logger log = LogManager.getLogger(RestGetVersionCheckAction.class);
    private static final String ENDPOINT_NAME = "content_manager_version_check_get";
    private static final String ENDPOINT_UNIQUE_NAME = "plugin:content_manager/version_check_get";

    private final Environment environment;
    private final ClusterService clusterService;
    private final ApiClient apiClient;
    private final ObjectMapper mapper;

    /**
     * Constructs a new RestGetVersionCheckAction.
     *
     * @param environment the node environment for reading VERSION.json
     * @param clusterService the cluster service for retrieving the cluster UUID
     */
    public RestGetVersionCheckAction(Environment environment, ClusterService clusterService) {
        this.environment = environment;
        this.clusterService = clusterService;
        this.apiClient = new ApiClient(ContentManagerPlugin.getVersion(environment));
        this.mapper = new ObjectMapper();
    }

    /**
     * Package-private constructor for dependency injection during unit tests.
     *
     * @param environment the node environment
     * @param clusterService the cluster service
     * @param apiClient the API client (can be mocked)
     */
    RestGetVersionCheckAction(
            Environment environment, ClusterService clusterService, ApiClient apiClient) {
        this.environment = environment;
        this.clusterService = clusterService;
        this.apiClient = apiClient;
        this.mapper = new ObjectMapper();
    }

    @Override
    public String getName() {
        return ENDPOINT_NAME;
    }

    @Override
    public List<Route> routes() {
        return List.of(
                new NamedRoute.Builder()
                        .path(PluginSettings.VERSION_CHECK_URI)
                        .method(GET)
                        .uniqueName(ENDPOINT_UNIQUE_NAME)
                        .build());
    }

    @Override
    public RestChannelConsumer prepareRequest(RestRequest request, NodeClient client) {
        return channel -> channel.sendResponse(this.handleRequest());
    }

    /**
     * Executes the version check operation.
     *
     * @return a BytesRestResponse containing the available updates or error
     * @throws IOException if an I/O error occurs while building the response
     */
    public BytesRestResponse handleRequest() throws IOException {
        try {
            String version = ContentManagerPlugin.getVersion(this.environment);
            if (version == null || version.isBlank()) {
                log.error(Constants.E_500_VERSION_NOT_FOUND);
                return new RestResponse(
                                Constants.E_500_VERSION_NOT_FOUND, RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                        .toBytesRestResponse();
            }

            String tag = "v" + version;
            SimpleHttpResponse ctiResponse = this.apiClient.getReleaseUpdates(tag);

            int ctiStatusCode = ctiResponse.getCode();
            if (ctiStatusCode < 200 || ctiStatusCode >= 300) {
                log.error(
                        "CTI API returned error for version check: status={}, body={}",
                        ctiStatusCode,
                        ctiResponse.getBodyText());
                RestStatus status =
                        RestStatus.fromCode(ctiStatusCode) != null
                                ? RestStatus.fromCode(ctiStatusCode)
                                : RestStatus.BAD_GATEWAY;
                return new RestResponse(ctiResponse.getBodyText(), status.getStatus())
                        .parseMessageAsJson()
                        .toBytesRestResponse();
            }

            JsonNode root = this.mapper.readTree(ctiResponse.getBodyText());
            JsonNode data = root.get("data");

            Release lastMajor = getLastRelease(data, "major");
            Release lastMinor = getLastRelease(data, "minor");
            Release lastPatch = getLastRelease(data, "patch");

            String uuid = this.clusterService.state().metadata().clusterUUID();
            String lastCheckDate =
                    OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

            return new VersionCheckResponse(
                            uuid, lastCheckDate, tag, lastMajor, lastMinor, lastPatch, RestStatus.OK.getStatus())
                    .toBytesRestResponse();

        } catch (Exception e) {
            log.error("Unexpected error during version check: {}", e.getMessage(), e);
            return new RestResponse(
                            Constants.E_500_CTI_UNREACHABLE, RestStatus.INTERNAL_SERVER_ERROR.getStatus())
                    .toBytesRestResponse();
        }
    }

    /**
     * Extracts the last (most recent) release from a category array in the CTI response.
     *
     * @param data the "data" node from the CTI API response
     * @param category the category name ("major", "minor", or "patch")
     * @return the last Release in the array, or null if the array is empty or missing
     */
    private Release getLastRelease(JsonNode data, String category) {
        if (data == null || !data.has(category)) {
            return null;
        }
        JsonNode array = data.get(category);
        if (!array.isArray() || array.isEmpty()) {
            return null;
        }
        try {
            List<Release> releases =
                    this.mapper.readValue(array.toString(), new TypeReference<List<Release>>() {});
            return releases.get(releases.size() - 1);
        } catch (Exception e) {
            log.warn("Failed to parse {} releases: {}", category, e.getMessage());
            return null;
        }
    }
}
