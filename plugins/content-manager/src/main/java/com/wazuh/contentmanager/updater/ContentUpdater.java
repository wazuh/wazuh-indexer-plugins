/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.updater;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ConsumersIndex;
import com.wazuh.contentmanager.model.cti.Changes;
import com.wazuh.contentmanager.model.cti.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.VisibleForTesting;

/** Class responsible for managing content updates by fetching and applying changes in chunks. */
public class ContentUpdater {
    private static final Logger log = LogManager.getLogger(ContentUpdater.class);
    private final ConsumersIndex consumersIndex;
    private final ContentIndex contentIndex;
    private final CTIClient ctiClient;
    private final Privileged privileged;
    private final PluginSettings pluginSettings;

    /** Exception thrown by the Content Updater in case of errors. */
    public static class ContentUpdateException extends RuntimeException {
        /**
         * Constructor method
         *
         * @param message Message to be thrown
         * @param cause Cause of the exception
         */
        public ContentUpdateException(String message, Throwable cause) {
            super(message, cause);
        }
    }

    /**
     * Constructor. Mainly used for testing purposes. Dependency injection.
     *
     * @param ctiClient the CTIClient to interact with the CTI API.
     * @param consumersIndex An object that handles context and consumer information.
     * @param contentIndex An object that handles content index interactions.
     */
    public ContentUpdater(
            CTIClient ctiClient,
            ConsumersIndex consumersIndex,
            ContentIndex contentIndex,
            Privileged privileged) {
        this.consumersIndex = consumersIndex;
        this.contentIndex = contentIndex;
        this.ctiClient = ctiClient;
        this.pluginSettings = PluginSettings.getInstance();
        this.privileged = privileged;
    }

    /**
     * This constructor is only used on tests.
     *
     * @param ctiClient mocked @CTIClient.
     * @param contentIndex mocked @ContentIndex.
     * @param pluginSettings mocked @PluginSettings.
     */
    @VisibleForTesting
    public ContentUpdater(
            CTIClient ctiClient,
            ConsumersIndex consumersIndex,
            ContentIndex contentIndex,
            Privileged privileged,
            PluginSettings pluginSettings) {
        this.consumersIndex = consumersIndex;
        this.contentIndex = contentIndex;
        this.ctiClient = ctiClient;
        this.pluginSettings = pluginSettings;
        this.privileged = privileged;
    }

    /**
     * Starts and orchestrates the process to update the content in the index with the latest changes
     * from the CTI API. The content needs an update when the "offset" and the "lastOffset" values are
     * different. In that case, the update process tries to bring the content up to date by querying
     * the CTI API for a list of changes to apply to the content. These changes are applied
     * sequentially. A maximum of {@link PluginSettings#MAX_CHANGES} changes are applied on each
     * iteration. When the update is completed, the value of "offset" is updated and equal to
     * "lastOffset" {@link ConsumersIndex#index(ConsumerInfo)}. If
     * the update fails, the "offset" is set to 0 to force a recovery from a snapshot.
     *
     * @return true if the updates were successfully applied, false otherwise.
     * @throws ContentUpdateException If there was an error fetching the changes.
     */
    public boolean update() throws ContentUpdateException {
        ConsumerInfo consumerInfo =
                this.consumersIndex.get(
                        this.pluginSettings.getContextId(), this.pluginSettings.getConsumerId());
        long currentOffset = consumerInfo.getOffset();
        long lastOffset = consumerInfo.getLastOffset();

        if (lastOffset == currentOffset) {
            log.info("No updates available. Current offset ({}) is up to date.", currentOffset);
            return true;
        }

        log.info("Updating [{}]", ContentIndex.INDEX_NAME);
        while (currentOffset < lastOffset) {
            long nextOffset =
                    Math.min(currentOffset + this.pluginSettings.getMaximumChanges(), lastOffset);
            Changes changes = this.privileged.getChanges(this.ctiClient, currentOffset, nextOffset);
            log.debug("Fetched offsets from {} to {}", currentOffset, nextOffset);

            // Update halted. Save current state and exit.
            if (changes == null) {
                log.error("Updated interrupted on offset [{}]", currentOffset);
                consumerInfo.setOffset(currentOffset);
                this.consumersIndex.index(consumerInfo);
                return false;
            }
            // Update failed. Force initialization from a snapshot.
            if (!this.applyChanges(changes)) {
                log.error("Updated finally failed on offset [{}]", currentOffset);
                consumerInfo.setOffset(0);
                consumerInfo.setLastOffset(0);
                this.consumersIndex.index(consumerInfo);
                return false;
            }

            currentOffset = nextOffset;
            log.debug("Update current offset to {}", currentOffset);
        }

        // Update consumer info.
        consumerInfo.setLastOffset(currentOffset);
        this.consumersIndex.index(consumerInfo);
        log.info("[{}] updated to offset [{}]", ContentIndex.INDEX_NAME, consumerInfo.getOffset());
        return true;
    }

    /**
     * Applies the fetched changes to the indexed content.
     *
     * @param changes Detected content changes.
     * @return true if the changes were successfully applied, false otherwise.
     */
    @VisibleForTesting
    protected boolean applyChanges(Changes changes) {
        try {
            this.contentIndex.patch(changes);
            return true;
        } catch (RuntimeException e) {
            return false;
        }
    }
}
