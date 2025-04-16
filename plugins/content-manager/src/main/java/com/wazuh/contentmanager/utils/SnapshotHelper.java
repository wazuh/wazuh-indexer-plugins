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
import org.opensearch.env.Environment;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;
import reactor.util.annotation.NonNull;

/** Helper class to handle indexing of snapshots */
public final class SnapshotHelper {

    private static final Logger log = LogManager.getLogger(SnapshotHelper.class);
    private static SnapshotHelper instance;
    private final CTIClient ctiClient;
    private final Environment environment;
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;

    public SnapshotHelper(
            @NonNull Environment environment,
            @NonNull ContextIndex contextIndex,
            @NonNull ContentIndex contentIndex) {
        this.ctiClient = CTIClient.getInstance();
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
    }

    public SnapshotHelper(
            @NonNull CTIClient ctiClient,
            @NonNull Environment environment,
            @NonNull ContextIndex contextIndex,
            @NonNull ContentIndex contentIndex) {
        this.ctiClient = ctiClient;
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
    }

    /**
     * Getter for the singleton object
     *
     * @param environment The environment to create files within
     * @param contextIndex The object in charge of indexing operations on the wazuh-context index
     * @param contentIndex The object in charge of indexing to the wazuh-cve index
     * @return a SnapshotHelper instance
     */
    public static synchronized SnapshotHelper getInstance(
            @NonNull Environment environment,
            @NonNull ContextIndex contextIndex,
            @NonNull ContentIndex contentIndex) {
        if (instance == null) {
            instance = new SnapshotHelper(environment, contextIndex, contentIndex);
        }
        return instance;
    }

    /**
     * Getter for the singleton object
     *
     * @param environment The environment to create files within
     * @param contextIndex The object in charge of indexing operations on the wazuh-context index
     * @param contentIndex The object in charge of indexing to the wazuh-cve index
     * @return a SnapshotHelper instance
     */
    public static synchronized SnapshotHelper getInstance(
            @NonNull CTIClient ctiClient,
            @NonNull Environment environment,
            @NonNull ContextIndex contextIndex,
            @NonNull ContentIndex contentIndex) {
        if (instance == null) {
            instance = new SnapshotHelper(ctiClient, environment, contextIndex, contentIndex);
        }
        return instance;
    }

    /**
     * Getter for the singleton object
     *
     * @return a SnapshotHelper instance
     * @throws IllegalStateException if the object was not initialized
     */
    public static synchronized SnapshotHelper getInstance() throws IllegalStateException {
        if (instance == null) {
            throw new IllegalStateException(
                    "Call getInstance(environment, contextIndex, contentIndex) first");
        }
        return instance;
    }

    /** Download, decompress and index a CTI snapshot */
    @VisibleForTesting
    void indexSnapshot() {
        if (this.contextIndex.getOffset() > 0) {
            return;
        }
        Privileged.doPrivilegedRequest(
                () -> {
                    Path snapshotZip =
                            this.ctiClient.download(this.contextIndex.getLastSnapshotLink(), this.environment);
                    Path outputDir = this.environment.resolveRepoFile("");

                    List<Path> snapshotJson = new ArrayList<>();
                    try (DirectoryStream<Path> stream =
                            Files.newDirectoryStream(
                                    outputDir,
                                    String.format(
                                            Locale.ROOT,
                                            "%s_%s_*.json",
                                            PluginSettings.CONTEXT_ID,
                                            PluginSettings.CONSUMER_ID))) {
                        Unzip.unzip(snapshotZip, outputDir);
                        for (Path path : stream) {
                            snapshotJson.add(path);
                        }
                        postUpdateCommand();
                        this.contentIndex.fromSnapshot(snapshotJson.get(0).toString());
                        Files.deleteIfExists(snapshotZip);
                        Files.deleteIfExists(snapshotJson.get(0));
                    } catch (IOException | NullPointerException e) {
                        log.error("Failed to index snapshot: {}", e.getMessage());
                    }
                    return null;
                });
    }

    /** Posts a command to the command manager API on a successful snapshot operation */
    private void postUpdateCommand() {
        CommandManagerClient.getInstance()
                .postCommand(Command.create(this.contextIndex.getLastOffset().toString()));
    }

    /**
     * Updates the context index with data from the CTI API
     *
     * @throws IOException thrown when indexing failed
     */
    @VisibleForTesting
    void updateContextIndex() throws IOException {
        ConsumerInfo consumerInfo = Privileged.doPrivilegedRequest(this.ctiClient::getCatalog);

        // DocWriteResponse.Result result = this.contextIndex.index(consumerInfo).getResult();

        IndexResponse response = this.contextIndex.index(consumerInfo);

        log.info(response.getResult());

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
    public void initializeCVEIndex() {
        try {
            updateContextIndex();
            indexSnapshot();
        } catch (IOException e) {
            log.error("Failed to initialize CVE Index from snapshot: {}", e.getMessage());
        }
    }

    public SnapshotHelper clearInstance() {
        instance = null;
        return instance;
    }
}
