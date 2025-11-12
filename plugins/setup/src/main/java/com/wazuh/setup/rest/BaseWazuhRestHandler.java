// src/main/java/com/wazuh/setup/rest/BaseWazuhRestHandler.java
package com.wazuh.setup.rest;

import org.opensearch.commons.authuser.User;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.BaseRestHandler;
import org.opensearch.rest.RestRequest;
import org.opensearch.OpenSearchSecurityException;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.node.NodeClient;

import java.util.Locale;
import java.util.Set;

public abstract class BaseWazuhRestHandler extends BaseRestHandler {

    protected static final String WAZUH_REST_API_PREFIX = "restapi:admin/wazuh/";
    protected final ThreadPool threadPool;

    protected BaseWazuhRestHandler(ThreadPool threadPool) {
        this.threadPool = threadPool;
    }

    /**
     * Check if the user has permission to access this endpoint
     */
    protected void checkAccessPermissions(RestRequest request) throws Exception {
        // Get user from thread context (injected by Security plugin)
        User user = (User) threadPool.getThreadContext()
            .getTransient("opendistro_security_user");

        if (user == null) {
            throw new OpenSearchSecurityException(
                "User not authenticated",
                RestStatus.UNAUTHORIZED
            );
        }

        String requiredPermission = WAZUH_REST_API_PREFIX + getEndpoint();

        // Check if user has the required permission
        if (!hasPermission(user, requiredPermission)) {
            throw new OpenSearchSecurityException(
                String.format(
                    Locale.ROOT,
                    "Insufficient permissions. Required: %s",
                    requiredPermission
                ),
                RestStatus.FORBIDDEN
            );
        }
    }

    /**
     * Check if user has the required permission in their roles
     */
    private boolean hasPermission(User user, String permission) {
        // In a real implementation, you'd use PrivilegesEvaluator
        // For POC, we'll do a simple check

        // Get user's backend roles
        Set<String> roles = (Set<String>) user.getRoles();

        if (roles.contains("all_access") || roles.contains("wazuh_admin")) {
            return true;
        }

        // In production, check against actual role permissions from security index
        // This is simplified for POC purposes
        return false;
    }

    /**
     * Each handler must define its endpoint
     * e.g., "setup", "policies/create", "policies/delete"
     */
    protected abstract String getEndpoint();

    @Override
    protected RestChannelConsumer prepareRequest(
        RestRequest request,
        NodeClient client
    ) {
        // Always check permissions first
        try {
            checkAccessPermissions(request);
            // Then proceed with actual request handling
            return handleApiRequest(request, client);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Actual request handling logic (after authorization)
     */
    protected abstract RestChannelConsumer handleApiRequest(
        RestRequest request,
        NodeClient client
    ) throws Exception;
}
