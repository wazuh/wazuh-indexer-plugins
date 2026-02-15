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
package com.wazuh.contentmanager.rest.services;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.rest.RestRequest;
import org.opensearch.transport.client.Client;

import java.util.List;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.cti.catalog.utils.IndexHelper;
import com.wazuh.contentmanager.engine.services.EngineService;
import com.wazuh.contentmanager.rest.model.RestResponse;
import com.wazuh.contentmanager.utils.Constants;
import com.wazuh.contentmanager.utils.DocumentValidations;

/**
 * Abstract handler for deleting content resources.
 *
 * <p>Implements the standard workflow for deletion:
 *
 * <ol>
 *   <li>Validates ID presence and format.
 *   <li>Ensures the resource exists and is in the Draft space.
 *   <li>Performs pre-delete validation (e.g., checking for dependent resources).
 *   <li>Removes the resource from external services (Engine/SAP).
 *   <li>Unlinks the resource from its parent (Integration/Policy).
 *   <li>Deletes the document from the index.
 *   <li>Updates the policy hash.
 * </ol>
 */
public abstract class AbstractDeleteAction extends AbstractContentAction {

    private static final Logger log = LogManager.getLogger(AbstractDeleteAction.class);

    public AbstractDeleteAction(EngineService engine) {
        super(engine);
    }

    @Override
    protected RestResponse executeRequest(RestRequest request, Client client) {
        String id = request.param(Constants.KEY_ID);

        try {
            // 1. Validation
            RestResponse validationError =
                    DocumentValidations.validateRequiredParam(id, Constants.KEY_ID);
            if (validationError != null) return validationError;

            validationError = DocumentValidations.validateUUID(id);
            if (validationError != null) {
                log.warn("Delete failed for {}: Invalid UUID [{}]", this.getResourceType(), id);
                return validationError;
            }

            if (!IndexHelper.indexExists(client, this.getIndexName())) {
                log.error("Delete failed: Index [{}] does not exist.", this.getIndexName());
                return new RestResponse(
                        "Index not found: " + this.getIndexName(),
                        RestStatus.INTERNAL_SERVER_ERROR.getStatus());
            }

            ContentIndex index = new ContentIndex(client, this.getIndexName(), null);
            if (!index.exists(id)) {
                log.warn("Delete failed: {} [{}] not found.", this.getResourceType(), id);
                return new RestResponse(
                        Constants.E_404_RESOURCE_NOT_FOUND, RestStatus.NOT_FOUND.getStatus());
            }

            String spaceError =
                    DocumentValidations.validateDocumentInSpace(
                            client, this.getIndexName(), id, this.getResourceType());
            if (spaceError != null) {
                log.warn("Delete failed: {} [{}] is not in Draft space.", this.getResourceType(), id);
                return new RestResponse(spaceError, RestStatus.BAD_REQUEST.getStatus());
            }

            // 2. Pre-delete validation
            validationError = this.validateDelete(client, id);
            if (validationError != null) {
                log.warn(
                        "Delete validation failed for {} [{}]: {}",
                        this.getResourceType(),
                        id,
                        validationError.getMessage());
                return validationError;
            }

            // 3. External Sync
            try {
                this.deleteExternalServices(id);
            } catch (Exception e) {
                log.warn(
                        "Failed to delete {} [{}] from external service. Reason: {}",
                        this.getResourceType(),
                        id,
                        e.getMessage());
            }

            // 4. Unlink Parent
            try {
                this.unlinkFromParent(client, id);
            } catch (Exception e) {
                log.warn(
                        "Failed to unlink {} [{}] from parent. Reason: {}",
                        this.getResourceType(),
                        id,
                        e.getMessage());
            }

            // 5. Delete from Index
            index.delete(id);

            // 6. Hash Update
            this.policyHashService.calculateAndUpdate(List.of(Space.DRAFT.toString()));

            log.info("Successfully deleted {} [{}]", this.getResourceType(), id);
            return new RestResponse(id, RestStatus.OK.getStatus());

        } catch (Exception e) {
            log.error(
                    "Unexpected error deleting {} [{}]. Reason: {}",
                    this.getResourceType(),
                    id,
                    e.getMessage());
            return new RestResponse(
                    "Internal Server Error. " + e.getMessage(), RestStatus.INTERNAL_SERVER_ERROR.getStatus());
        }
    }

    protected abstract String getIndexName();

    protected abstract String getResourceType();

    /**
     * Validates if the requested delete can be performed or not
     *
     * @param client Client used to search in the indices
     * @param id UUID of the resource to check
     * @return null if the resource can be deleted otherwise a RestResponse with the reason why it
     *     cannot
     */
    protected RestResponse validateDelete(Client client, String id) {
        return null;
    }

    /**
     * Synchronizes the deletion of the resource with external services (SAP).
     *
     * @param id Resource UUID
     */
    protected abstract void deleteExternalServices(String id);

    /**
     * Unlinks the just deleted resource to its parent container (e.g., deleting Rule ID to
     * Integration).
     */
    protected abstract void unlinkFromParent(Client client, String id);
}
