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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.ExceptionsHelper;
import org.opensearch.action.search.SearchRequest;
import org.opensearch.action.support.ActionFilters;
import org.opensearch.action.support.HandledTransportAction;
import org.opensearch.core.action.ActionListener;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.index.query.QueryBuilders;
import org.opensearch.search.builder.SearchSourceBuilder;
import org.opensearch.tasks.Task;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Locale;
import java.util.UUID;

import com.wazuh.contentmanager.action.ContentCreateRequest;
import com.wazuh.contentmanager.action.ContentResponse;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Resource;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.service.IntegrationService;
import com.wazuh.contentmanager.cti.catalog.service.ResourceLockService;
import com.wazuh.contentmanager.cti.catalog.service.ResourceLockTimeoutException;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsService;
import com.wazuh.contentmanager.cti.catalog.service.SecurityAnalyticsServiceImpl;
import com.wazuh.contentmanager.cti.catalog.service.SpaceService;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.rest.utils.PayloadValidations;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.MockSecurityAnalyticsService;
import com.wazuh.contentmanager.utils.YamlUtils;

/**
 * Abstract transport action for creating content resources (non-Spaces variant).
 *
 * <p>Mirrors the business logic from {@code AbstractCreateAction.executeRequest()}. Resources are
 * always created in the DRAFT space.
 */
public abstract class AbstractTransportCreateAction
        extends HandledTransportAction<ContentCreateRequest, ContentResponse> {

    private static final Logger log = LogManager.getLogger(AbstractTransportCreateAction.class);
    protected static final ObjectMapper MAPPER = new ObjectMapper();
    protected final PayloadValidations documentValidations = new PayloadValidations();
    protected final Client client;
    protected final EngineService engine;
    protected final ResourceLockService resourceLockService;

    protected AbstractTransportCreateAction(
            String actionName,
            TransportService transportService,
            ActionFilters actionFilters,
            Client client,
            EngineService engine) {
        super(actionName, transportService, actionFilters, ContentCreateRequest::new);
        this.client = client;
        this.engine = engine;
        this.resourceLockService = new ResourceLockService(client, transportService.getThreadPool());
    }

    @Override
    protected void doExecute(
            Task task, ContentCreateRequest request, ActionListener<ContentResponse> listener) {
        SecurityAnalyticsService securityAnalyticsService;
        if (PluginSettings.getInstance().isEngineMockEnabled()) {
            securityAnalyticsService = new MockSecurityAnalyticsService();
        } else {
            securityAnalyticsService = new SecurityAnalyticsServiceImpl(client);
        }
        SpaceService spaceService = new SpaceService(client);
        IntegrationService integrationService = new IntegrationService(client);

        TransportActionHelper.validateDraftPolicyExists(
                client,
                ActionListener.wrap(
                        policyError -> {
                            if (policyError != null) {
                                listener.onResponse(
                                        new ContentResponse(
                                                policyError.getMessage(), RestStatus.fromCode(policyError.getStatus())));
                                return;
                            }
                            executeCreateWorkflowAsync(
                                    request,
                                    client,
                                    spaceService,
                                    securityAnalyticsService,
                                    integrationService,
                                    listener);
                        },
                        e -> respondWithError(listener, e)));
    }

    private void executeCreateWorkflowAsync(
            ContentCreateRequest request,
            Client client,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            IntegrationService integrationService,
            ActionListener<ContentResponse> listener) {
        // 1. Validate body is present
        byte[] body = request.getBodyContent();
        if (body == null || body.length == 0) {
            log.warn(
                    Constants.W_LOG_OPERATION_FAILED,
                    "Creation",
                    this.getResourceType(),
                    "Request body is missing");
            listener.onResponse(
                    new ContentResponse(Constants.E_400_INVALID_REQUEST_BODY, RestStatus.BAD_REQUEST));
            return;
        }

        try {
            String rawYaml = null;
            JsonNode rootNode;
            ObjectNode resourceNode;
            boolean isYaml = "yaml".equals(request.getContentType());

            if (isYaml && this.supportsYamlField()) {
                try {
                    String yamlBody = new String(body, java.nio.charset.StandardCharsets.UTF_8);
                    rootNode = YamlUtils.fromYaml(yamlBody);
                } catch (IOException e) {
                    log.warn(
                            Constants.W_LOG_OPERATION_FAILED,
                            "Creation",
                            this.getResourceType(),
                            "Invalid YAML format. Reason: " + e.getMessage());
                    listener.onResponse(
                            new ContentResponse(
                                    Constants.E_400_INVALID_REQUEST_BODY + e.getMessage(), RestStatus.BAD_REQUEST));
                    return;
                }

                RestResponse validationError =
                        this.documentValidations.validateResourcePayload(
                                rootNode, this.requiresIntegrationId());
                if (validationError != null) {
                    log.warn(
                            Constants.W_LOG_OPERATION_FAILED,
                            "Payload structure validation",
                            this.getResourceType(),
                            validationError.getMessage());
                    listener.onResponse(
                            new ContentResponse(
                                    validationError.getMessage(), RestStatus.fromCode(validationError.getStatus())));
                    return;
                }
                resourceNode = (ObjectNode) rootNode.get(Constants.KEY_RESOURCE);
                rawYaml = YamlUtils.toYaml(resourceNode);
            } else {
                try {
                    rootNode = MAPPER.readTree(new ByteArrayInputStream(body));
                } catch (IOException e) {
                    log.warn(
                            Constants.W_LOG_OPERATION_FAILED,
                            "Creation",
                            this.getResourceType(),
                            "Invalid JSON format. Reason: " + e.getMessage());
                    listener.onResponse(
                            new ContentResponse(
                                    Constants.E_400_INVALID_REQUEST_BODY + e.getMessage(), RestStatus.BAD_REQUEST));
                    return;
                }

                RestResponse validationError =
                        this.documentValidations.validateResourcePayload(
                                rootNode, this.requiresIntegrationId());
                if (validationError != null) {
                    log.warn(
                            Constants.W_LOG_OPERATION_FAILED,
                            "Payload structure validation",
                            this.getResourceType(),
                            validationError.getMessage());
                    listener.onResponse(
                            new ContentResponse(
                                    validationError.getMessage(), RestStatus.fromCode(validationError.getStatus())));
                    return;
                }
                resourceNode = (ObjectNode) rootNode.get(Constants.KEY_RESOURCE);
            }

            // 3. Resource Specific Validation (async)
            final String finalRawYaml = rawYaml;
            final JsonNode finalRootNode = rootNode;
            final ObjectNode finalResourceNode = resourceNode;
            this.validatePayload(
                    client,
                    rootNode,
                    resourceNode,
                    integrationService,
                    ActionListener.wrap(
                            validationError -> {
                                if (validationError != null) {
                                    log.warn(
                                            Constants.W_LOG_OPERATION_FAILED,
                                            "Validation",
                                            this.getResourceType(),
                                            validationError.getMessage());
                                    listener.onResponse(
                                            new ContentResponse(
                                                    validationError.getMessage(),
                                                    RestStatus.fromCode(validationError.getStatus())));
                                    return;
                                }
                                createWithLimitGuard(
                                        finalRootNode,
                                        finalResourceNode,
                                        finalRawYaml,
                                        client,
                                        spaceService,
                                        securityAnalyticsService,
                                        integrationService,
                                        listener);
                            },
                            e -> respondWithError(listener, e)));

        } catch (Exception e) {
            respondWithError(listener, e);
        }
    }

    /**
     * Serializes the limit-check-then-create sequence per resource type/space so concurrent requests
     * cannot all observe a stale count and overshoot the configured max. Acquires the resource lock,
     * checks the limit, then proceeds with the async creation chain. The lock is released once that
     * chain completes, whether it succeeds or fails.
     */
    private void createWithLimitGuard(
            JsonNode rootNode,
            ObjectNode resourceNode,
            String rawYaml,
            Client client,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            IntegrationService integrationService,
            ActionListener<ContentResponse> listener) {
        // 3b. Serialize the limit-check-then-create sequence per resource type/space so concurrent
        // requests cannot all observe a stale count and overshoot the configured max.
        String space = Space.DRAFT.toString();
        this.resourceLockService.acquire(
                this.getResourceType(),
                space,
                ActionListener.wrap(
                        lockId -> {
                            ActionListener<ContentResponse> lockReleasingListener =
                                    ActionListener.runAfter(listener, () -> this.resourceLockService.release(lockId));

                            this.checkResourceLimitAsync(
                                    client,
                                    space,
                                    ActionListener.wrap(
                                            limitError -> {
                                                if (limitError != null) {
                                                    lockReleasingListener.onResponse(
                                                            new ContentResponse(
                                                                    limitError.getMessage(),
                                                                    RestStatus.fromCode(limitError.getStatus())));
                                                    return;
                                                }
                                                afterValidation(
                                                        rootNode,
                                                        resourceNode,
                                                        rawYaml,
                                                        client,
                                                        spaceService,
                                                        securityAnalyticsService,
                                                        integrationService,
                                                        lockReleasingListener);
                                            },
                                            e -> respondWithError(lockReleasingListener, e)));
                        },
                        e -> {
                            if (ExceptionsHelper.unwrap(e, ResourceLockTimeoutException.class) != null) {
                                log.warn(
                                        "Failed to acquire resource-creation lock for [{}]: {}",
                                        this.getResourceType(),
                                        e.getMessage());
                                listener.onResponse(
                                        new ContentResponse(
                                                Constants.E_429_RESOURCE_LOCK_TIMEOUT, RestStatus.TOO_MANY_REQUESTS));
                                return;
                            }
                            respondWithError(listener, e);
                        }));
    }

    /**
     * Checks whether creating another resource of this type in the given space would exceed the
     * configured limit. Must be called while holding the {@link #resourceLockService} lock for
     * (resource type, space) so the count it observes stays valid until the resource is created.
     *
     * @param client The OpenSearch client.
     * @param space The space to count existing resources in.
     * @param listener Receives a {@code BAD_REQUEST} {@link RestResponse} if the limit would be
     *     exceeded, or {@code null} if creation may proceed.
     */
    private void checkResourceLimitAsync(
            Client client, String space, ActionListener<RestResponse> listener) {
        int max = this.getMaxAllowed();
        SearchRequest countRequest = new SearchRequest(this.getIndexName());
        SearchSourceBuilder countSource = new SearchSourceBuilder();
        countSource.query(QueryBuilders.termQuery(Constants.Q_SPACE_NAME, space));
        countSource.size(0);
        countSource.trackTotalHits(true);
        countRequest.source(countSource);
        client.search(
                countRequest,
                ActionListener.wrap(
                        countResponse -> {
                            long count =
                                    countResponse.getHits().getTotalHits() != null
                                            ? countResponse.getHits().getTotalHits().value()
                                            : 0;
                            if (count >= max) {
                                log.info(this.getMaxReachedLogFormat(), max);
                                listener.onResponse(
                                        new RestResponse(
                                                String.format(Locale.ROOT, this.getTooManyResourcesMessageFormat(), max),
                                                RestStatus.BAD_REQUEST.getStatus()));
                            } else {
                                listener.onResponse(null);
                            }
                        },
                        e -> {
                            log.warn(
                                    "Failed to count existing {} for limit check: {}",
                                    this.getResourceType(),
                                    e.getMessage());
                            listener.onResponse(null);
                        }));
    }

    private void afterValidation(
            JsonNode rootNode,
            ObjectNode resourceNode,
            String rawYaml,
            Client client,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            IntegrationService integrationService,
            ActionListener<ContentResponse> listener) {
        // 4. Generate ID and Metadata
        String id = UUID.randomUUID().toString();
        resourceNode.put(Constants.KEY_ID, id);

        String currentTimestamp = getCurrentDate();
        Resource.setCreationTime(resourceNode, currentTimestamp);
        Resource.setLastModificationTime(resourceNode, currentTimestamp);
        Resource.nestMetadataFields(resourceNode);

        if (!resourceNode.has(Constants.KEY_ENABLED)) {
            resourceNode.put(Constants.KEY_ENABLED, true);
        }

        // 6. External Sync (async)
        this.syncExternalServices(
                id,
                resourceNode,
                securityAnalyticsService,
                ActionListener.wrap(
                        syncError -> {
                            if (syncError != null) {
                                if (syncError.getStatus() < 500) {
                                    log.warn(
                                            Constants.E_LOG_FAILED_TO,
                                            "sync",
                                            this.getResourceType(),
                                            id,
                                            "with external services (Engine/SAP). Reason: " + syncError.getMessage());
                                } else {
                                    log.error(
                                            Constants.E_LOG_FAILED_TO,
                                            "sync",
                                            this.getResourceType(),
                                            id,
                                            "with external services (Engine/SAP). Reason: " + syncError.getMessage());
                                }
                                listener.onResponse(
                                        new ContentResponse(
                                                syncError.getMessage(), RestStatus.fromCode(syncError.getStatus())));
                                return;
                            }
                            afterSync(
                                    id,
                                    rootNode,
                                    resourceNode,
                                    rawYaml,
                                    client,
                                    spaceService,
                                    securityAnalyticsService,
                                    integrationService,
                                    listener);
                        },
                        e -> respondWithError(listener, e)));
    }

    private void afterSync(
            String id,
            JsonNode rootNode,
            ObjectNode resourceNode,
            String rawYaml,
            Client client,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            IntegrationService integrationService,
            ActionListener<ContentResponse> listener) {
        // 7. Indexing (async)
        ContentIndex index = new ContentIndex(client, this.getIndexName(), null);
        ObjectNode ctiWrapper = new Resource().wrapResource(resourceNode, Space.DRAFT.toString());

        if (this.supportsYamlField()) {
            if (rawYaml != null) {
                ctiWrapper.put(Constants.KEY_YAML, rawYaml);
            } else {
                ctiWrapper.put(Constants.KEY_YAML, YamlUtils.toYaml(resourceNode));
            }
        }

        index.create(
                id,
                ctiWrapper,
                ActionListener.wrap(
                        indexResponse ->
                                afterIndex(
                                        id,
                                        rootNode,
                                        index,
                                        client,
                                        spaceService,
                                        securityAnalyticsService,
                                        integrationService,
                                        listener),
                        e -> respondWithError(listener, e)));
    }

    private void afterIndex(
            String id,
            JsonNode rootNode,
            ContentIndex index,
            Client client,
            SpaceService spaceService,
            SecurityAnalyticsService securityAnalyticsService,
            IntegrationService integrationService,
            ActionListener<ContentResponse> listener) {
        // 8. Link to Parent (async)
        this.linkToParent(
                client,
                id,
                rootNode,
                integrationService,
                ActionListener.wrap(
                        v -> afterLink(id, spaceService, listener),
                        e -> {
                            log.error(
                                    Constants.E_LOG_FAILED_TO,
                                    "link",
                                    this.getResourceType(),
                                    id,
                                    "to parent resource. Rolling back. Reason: " + e.getMessage());
                            index.delete(id);
                            this.rollbackExternalServices(id, securityAnalyticsService);
                            respondWithError(listener, e);
                        }));
    }

    private void afterLink(
            String id, SpaceService spaceService, ActionListener<ContentResponse> listener) {
        // 9. Update Hash (async)
        spaceService.calculateAndUpdate(
                List.of(Space.DRAFT.toString()),
                ActionListener.wrap(
                        changedSpaces -> {
                            log.info(Constants.I_LOG_SUCCESS, "Created", this.getResourceType(), id);
                            listener.onResponse(new ContentResponse(id, RestStatus.CREATED));
                        },
                        e -> respondWithError(listener, e)));
    }

    private void respondWithError(ActionListener<ContentResponse> listener, Exception e) {
        RestResponse classified = TransportActionHelper.classifyException(e);
        if (classified != null) {
            log.warn(
                    Constants.W_LOG_OPERATION_FAILED,
                    "Creating",
                    this.getResourceType(),
                    classified.getMessage());
            listener.onResponse(
                    new ContentResponse(
                            classified.getMessage(), RestStatus.fromCode(classified.getStatus())));
            return;
        }
        log.error(
                Constants.E_LOG_OPERATION_FAILED,
                "creating",
                this.getResourceType(),
                "Reason: " + e.getMessage());
        listener.onResponse(
                new ContentResponse(
                        Constants.E_500_INTERNAL_SERVER_ERROR, RestStatus.INTERNAL_SERVER_ERROR));
    }

    protected String getCurrentDate() {
        return Instant.now().truncatedTo(ChronoUnit.SECONDS).toString();
    }

    protected boolean supportsYamlField() {
        return false;
    }

    protected boolean requiresIntegrationId() {
        return true;
    }

    protected abstract String getIndexName();

    protected abstract String getResourceType();

    /**
     * @return The configured maximum number of resources of this type allowed per space.
     */
    protected abstract int getMaxAllowed();

    /**
     * @return The {@code String.format} message template (taking the max as its sole argument)
     *     returned to the client when the limit is reached.
     */
    protected abstract String getTooManyResourcesMessageFormat();

    /**
     * @return The log message template (taking the max as its sole argument) logged when the limit is
     *     reached.
     */
    protected abstract String getMaxReachedLogFormat();

    protected abstract void validatePayload(
            Client client,
            JsonNode root,
            JsonNode resource,
            IntegrationService integrationService,
            ActionListener<RestResponse> listener);

    protected abstract void syncExternalServices(
            String id,
            JsonNode resource,
            SecurityAnalyticsService securityAnalyticsService,
            ActionListener<RestResponse> listener);

    protected void rollbackExternalServices(
            String id, SecurityAnalyticsService securityAnalyticsService) {}

    protected abstract void linkToParent(
            Client client,
            String id,
            JsonNode root,
            IntegrationService integrationService,
            ActionListener<Void> listener);
}
