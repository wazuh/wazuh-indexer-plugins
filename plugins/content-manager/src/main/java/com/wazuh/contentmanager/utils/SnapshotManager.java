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
package com.wazuh.contentmanager.utils;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.env.Environment;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.concurrent.Semaphore;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.cti.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;

/** Helper class to handle indexing of snapshots */
public class SnapshotManager {
    private static final Logger log = LogManager.getLogger(SnapshotManager.class);
    private final CTIClient ctiClient;
    private CommandManagerClient commandClient;
    private final Environment environment;
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;
    private final Privileged privileged;
    private final Semaphore semaphore = new Semaphore(1);
    private final PluginSettings pluginSettings;

    /**
     * Constructor.
     *
     * @param environment Needed for snapshot file handling.
     * @param contextIndex Handles context and consumer related metadata.
     * @param contentIndex Handles indexed content.
     */
    public SnapshotManager(
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex,
            Privileged privileged) {
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
        this.privileged = privileged;
        this.ctiClient = privileged.doPrivilegedRequest(CTIClient::getInstance);
        this.pluginSettings = PluginSettings.getInstance();
    }

    /**
     * Alternate constructor that allows injecting CTIClient for test purposes. Dependency injection.
     *
     * @param ctiClient Instance of CTIClient.
     * @param environment Needed for snapshot file handling.
     * @param contextIndex Handles context and consumer related metadata.
     * @param contentIndex Handles indexed content.
     */
    @VisibleForTesting
    protected SnapshotManager(
            CTIClient ctiClient,
            CommandManagerClient client,
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex,
            Privileged privileged,
            PluginSettings pluginSettings) {
        this.ctiClient = ctiClient;
        this.commandClient = client;
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
        this.privileged = privileged;
        this.pluginSettings = pluginSettings;
    }

    /**
     * Initializes the content if {@code offset == 0}. This method downloads, decompresses and indexes
     * a CTI snapshot.
     */
    protected void indexSnapshot(ConsumerInfo consumerInfo) {
        if (consumerInfo.getOffset() == 0) {
            log.info("Initializing [{}] index from a snapshot", ContentIndex.INDEX_NAME);
            this.privileged.doPrivilegedRequest(
                    () -> {
                        // Download snapshot.
                        Path snapshotZip =
                                this.ctiClient.download(consumerInfo.getLastSnapshotLink(), this.environment);
                        Path outputDir = this.environment.tmpFile();

                        try (DirectoryStream<Path> stream = this.getStream(outputDir)) {
                            // Unzip snapshot.
                            this.unzip(snapshotZip, outputDir);
                            Path snapshotJson = stream.iterator().next();
                            // Index snapshot.
                            long offset = this.contentIndex.fromSnapshot(snapshotJson.toString());
                            // Update the offset.
                            consumerInfo.setOffset(offset);
                            this.contextIndex.index(consumerInfo);
                            // Send command.
                            privileged.postUpdateCommand(this.commandClient, consumerInfo);
                            // Remove snapshot.
                            Files.deleteIfExists(snapshotZip);
                            Files.deleteIfExists(snapshotJson);
                        } catch (IOException | NullPointerException e) {
                            log.error("Failed to index snapshot: {}", e.getMessage());
                        }
                        return null;
                    });
        }
    }

    /**
     * Wrapper method to handle unzipping files
     *
     * @param snapshotZip The Path to the zip file
     * @param outputDir The output directory to extract files to
     * @throws IOException Risen from unzip()
     */
    protected void unzip(Path snapshotZip, Path outputDir) throws IOException {
        Unzip.unzip(snapshotZip, outputDir);
    }

    /**
     * Wrapper method to make newDirectoryStream() stubbable
     *
     * @param outputDir The output directory
     * @return A DirectoryStream Path
     * @throws IOException rethrown from newDirectoryStream()
     */
    protected DirectoryStream<Path> getStream(Path outputDir) throws IOException {
        return Files.newDirectoryStream(
                outputDir,
                String.format(
                        Locale.ROOT,
                        "%s_%s_*.json",
                        this.pluginSettings.getContextId(),
                        this.pluginSettings.getConsumerId()));
    }

    /**
     * Updates the context index with data from the CTI API
     *
     * @throws IOException thrown when indexing failed
     */
    protected ConsumerInfo initConsumer() throws IOException {
        ConsumerInfo current =
                this.contextIndex.get(
                        this.pluginSettings.getContextId(), this.pluginSettings.getConsumerId());
        ConsumerInfo latest = this.ctiClient.getConsumerInfo();
        log.debug("Current consumer info: {}", current);
        log.debug("Latest consumer info: {}", latest);

        // Consumer is not yet initialized. Initialize to latest.
        if (current == null || current.getOffset() == 0) {
            log.debug("Initializing consumer: {}", latest);
            if (this.contextIndex.index(latest)) {
                log.info(
                        "Successfully initialized consumer [{}][{}]", latest.getContext(), latest.getName());
            } else {
                throw new IOException(
                        String.format(
                                Locale.ROOT,
                                "Failed to initialize consumer [%s][%s]",
                                latest.getContext(),
                                latest.getName()));
            }
            current = latest;
        }
        // Consumer is initialized and up-to-date.
        else if (current.getOffset() == latest.getLastOffset()) {
            log.info(
                    "Consumer is up-to-date (offset {} == {}). Skipping...",
                    current.getOffset(),
                    latest.getLastOffset());
        }
        // Consumer is initialized but out-of-date.
        else {
            log.info("Consumer already initialized (offset {} != 0). Skipping...", current.getOffset());
            current.setLastOffset(latest.getLastOffset());
            current.setLastSnapshotLink(latest.getLastSnapshotLink());
            this.contextIndex.index(current);
        }
        return current;
    }

    /** Trigger method for content initialization */
    public void initialize() {
        try {
            this.semaphore.acquire();
            // The Command Manager client needs the cluster to be up (depends on PluginSettings),
            // so we initialize it here once the node is up and ready.
            this.commandClient = this.privileged.doPrivilegedRequest(CommandManagerClient::getInstance);
            ConsumerInfo consumerInfo = this.initConsumer();
            this.indexSnapshot(consumerInfo);
            semaphore.release();
        } catch (IOException | InterruptedException e) {
            log.error("Failed to initialize: {}", e.getMessage());
        }
    }
}
