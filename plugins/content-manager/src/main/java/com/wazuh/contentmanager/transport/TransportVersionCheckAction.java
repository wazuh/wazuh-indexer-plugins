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
package com.wazuh.contentmanager.transport;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.apache.hc.client5.http.async.methods.SimpleHttpResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.inject.Inject;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.env.Environment;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;

import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.ContentManagerPlugin;
import com.wazuh.contentmanager.action.VersionCheckAction;
import com.wazuh.contentmanager.action.VersionCheckRequest;
import com.wazuh.contentmanager.action.VersionCheckResponse;
import com.wazuh.contentmanager.cti.catalog.client.ApiClient;
import com.wazuh.contentmanager.cti.catalog.model.Release;
import com.wazuh.contentmanager.utils.Constants;

/**
 * Transport action for GET /version/check. Queries the CTI API to determine available Wazuh version
 * updates and returns the result as structured JSON.
 */
public class TransportVersionCheckAction
        extends HandledTransportAction<VersionCheckRequest, VersionCheckResponse> {

    private static final Logger log = LogManager.getLogger(TransportVersionCheckAction.class);

    private final Environment environment;
    private final ClusterService clusterService;
    private final ObjectMapper mapper = new ObjectMapper();

    @Inject
    public TransportVersionCheckAction(
            TransportService transportService,
            ActionFilters actionFilters,
            Environment environment,
            ClusterService clusterService) {
        super(VersionCheckAction.NAME, transportService, actionFilters, VersionCheckRequest::new);
        this.environment = environment;
        this.clusterService = clusterService;
    }

    @Override
    protected void doExecute(
            Task task, VersionCheckRequest request, ActionListener<VersionCheckResponse> listener) {
        try {
            String version = ContentManagerPlugin.getVersion(this.environment);
            if (version == null || version.isBlank()) {
                log.error(Constants.E_500_VERSION_NOT_FOUND);
                listener.onResponse(
                        new VersionCheckResponse(
                                Constants.E_500_VERSION_NOT_FOUND, RestStatus.INTERNAL_SERVER_ERROR));
                return;
            }

            String tag = "v" + version;
            ApiClient apiClient = new ApiClient();
            SimpleHttpResponse ctiResponse = apiClient.getReleaseUpdates(tag);

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
                listener.onResponse(
                        new VersionCheckResponse(ctiResponse.getBodyText(), status).parseMessageAsJson());
                return;
            }

            JsonNode root = this.mapper.readTree(ctiResponse.getBodyText());
            JsonNode data = root.get("data");

            Release lastMajor = this.getLastRelease(data, "major");
            Release lastMinor = this.getLastRelease(data, "minor");
            Release lastPatch = this.getLastRelease(data, "patch");

            String uuid = this.clusterService.state().metadata().clusterUUID();
            String lastCheckDate =
                    OffsetDateTime.now(ZoneOffset.UTC).format(DateTimeFormatter.ISO_OFFSET_DATE_TIME);

            // Build the structured message object matching VersionCheckResponse format
            Map<String, Object> messageMap = new HashMap<>();
            messageMap.put("uuid", uuid);
            messageMap.put("last_check_date", lastCheckDate);
            messageMap.put("current_version", tag);
            messageMap.put("last_available_major", releaseToMap(lastMajor));
            messageMap.put("last_available_minor", releaseToMap(lastMinor));
            messageMap.put("last_available_patch", releaseToMap(lastPatch));

            // Serialize message as JSON string but pass parsed object for structured output
            String messageJson = this.mapper.writeValueAsString(messageMap);
            listener.onResponse(new VersionCheckResponse(messageJson, RestStatus.OK, messageMap));

        } catch (Exception e) {
            log.error("Unexpected error during version check: {}", e.getMessage(), e);
            listener.onResponse(
                    new VersionCheckResponse(
                            Constants.E_500_CTI_UNREACHABLE, RestStatus.INTERNAL_SERVER_ERROR));
        }
    }

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
            return releases.getLast();
        } catch (Exception e) {
            log.warn("Failed to parse {} releases: {}", category, e.getMessage());
            return null;
        }
    }

    @SuppressWarnings("unchecked")
    private Map<String, Object> releaseToMap(Release release) {
        if (release == null) {
            return new HashMap<>();
        }
        return this.mapper.convertValue(release, Map.class);
    }
}
