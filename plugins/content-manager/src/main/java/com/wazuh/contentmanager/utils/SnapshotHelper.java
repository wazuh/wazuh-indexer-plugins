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
import org.opensearch.action.DocWriteResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.cluster.metadata.MappingMetadata;
import org.opensearch.env.Environment;
import org.opensearch.threadpool.ThreadPool;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Locale;
import java.util.Objects;
import java.util.concurrent.Executor;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;

/** Helper class to handle indexing of snapshots */
public class SnapshotHelper implements ClusterStateListener {
    private static final Logger log = LogManager.getLogger(SnapshotHelper.class);
    private ThreadPool threadPool;
    private final CTIClient ctiClient;
    private final Environment environment;
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;

    /**
     * Constructor.
     *
     * @param threadPool Used to launch the snapshot index task in its own thread
     * @param environment Needed for snapshot file handling.
     * @param contextIndex Handles context and consumer related metadata.
     * @param contentIndex Handles indexed content.
     */
    public SnapshotHelper(
            ThreadPool threadPool,
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex) {
        this.threadPool = threadPool;
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
        this.ctiClient = Privileged.doPrivilegedRequest(CTIClient::getInstance);
    }

    /**
     * Alternate constructor that allows injecting CTIClient for test purposes.
     *
     * @param ctiClient Instance of CTIClient.
     * @param environment Needed for snapshot file handling.
     * @param contextIndex Handles context and consumer related metadata.
     * @param contentIndex Handles indexed content.
     */
    protected SnapshotHelper(
            CTIClient ctiClient,
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex) {
        this.ctiClient = ctiClient;
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
    }

    /**
     * Initializes the content if {@code offset == 0}. This method downloads, decompresses and indexes
     * a CTI snapshot.
     */
    protected void indexSnapshot() {
        if (this.contextIndex.getOffset() == 0) {
            Privileged.doPrivilegedRequest(
                    () -> {
                        // Download
                        Path snapshotZip =
                                this.ctiClient.download(this.contextIndex.getLastSnapshotLink(), this.environment);
                        Path outputDir = this.environment.resolveRepoFile("");

                        try (DirectoryStream<Path> stream = this.getStream(outputDir)) {
                            this.unzip(snapshotZip, outputDir);
                            Path snapshotJson = stream.iterator().next();
                            this.contentIndex.fromSnapshot(snapshotJson.toString());

                            this.postUpdateCommand();
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
                        Locale.ROOT, "%s_%s_*.json", PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID));
    }

    /** Posts a command to the command manager API on a successful snapshot operation */
    protected void postUpdateCommand() {
        Privileged.doPrivilegedRequest(
                () -> {
                    CommandManagerClient.getInstance()
                            .postCommand(Command.create(String.valueOf(this.contextIndex.getLastOffset())));
                    return null;
                });
    }

    /**
     * Updates the context index with data from the CTI API
     *
     * @throws IOException thrown when indexing failed
     */
    protected void updateContextIndex() throws IOException {
        ConsumerInfo consumerInfo = this.ctiClient.getCatalog();

        if (consumerInfo == null) {
            throw new IOException("Consumer Information is null. Skipping indexing");
        }
        IndexResponse response = this.contextIndex.index(consumerInfo);

        if (response.getResult().equals(DocWriteResponse.Result.CREATED)
                || response.getResult().equals(DocWriteResponse.Result.UPDATED)) {
            log.info("Successfully initialized consumer [{}]", consumerInfo.getContext());
        } else {
            throw new IOException(
                    String.format(
                            Locale.ROOT,
                            "Consumer indexing operation returned with unexpected result [%s]",
                            response.getResult()));
        }
    }

    /** Trigger method for a CVE index initialization from a snapshot */
    public void initialize() {
        try {
            this.updateContextIndex();
            this.indexSnapshot();
        } catch (IOException e) {
            log.error("Failed to initialize CVE Index from snapshot: {}", e.getMessage());
        }
    }

    /**
     * This is part of the ClusterStateListener interface. It is used to launch the indexing of the
     * CVE snapshot upon detection of a new mapping being loaded into the "wazuh-cve" index
     *
     * @param event The event that allows us to detect the state change
     */
    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        // Get index information from current and previous cluster state
        IndexMetadata previousIndexMetadata =
                event.previousState().metadata().index(ContentIndex.INDEX_NAME);
        IndexMetadata currentIndexMetadata = event.state().metadata().index(ContentIndex.INDEX_NAME);

        // Declare mappings variables
        MappingMetadata previousMappings = null;
        MappingMetadata currentMappings;

        // If previous index state's metadata is null, don't try to its mappings
        if (previousIndexMetadata != null) {
            previousMappings = previousIndexMetadata.mapping();
        }

        // Don't move forward unless there is index metadata in the current state
        if (currentIndexMetadata == null) {
            return;
        }

        // At this point we can safely read the current mapping
        currentMappings = currentIndexMetadata.mapping();

        // Return when mappings haven't changed
        if (Objects.equals(currentMappings, previousMappings)) {
            return;
        }

        // Return when currentMappings is null
        if (currentMappings == null) {
            return;
        }

        // Make sure the current mappings are not the dynamically generated ones
        Object dynamicField = currentMappings.getSourceAsMap().get("dynamic");
        if (dynamicField == null) {
            return;
        }
        if (!dynamicField.equals("strict")) {
            return;
        }

        // Execute initialization in its own separate thread.
        // This is necessary to avoid blocking the engine.
        Executor executor = threadPool.executor(ThreadPool.Names.GENERIC);
        executor.execute(this::initialize);
    }
}
