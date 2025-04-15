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
import org.opensearch.env.Environment;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Objects;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.client.CommandManagerClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.commandmanager.Command;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Utility class responsible for initializing and indexing snapshot-based CVE data. This class
 * coordinates with various injected components to:
 *
 * <ul>
 *   <li>Download and extract CTI snapshot data
 *   <li>Index metadata in the context index
 *   <li>Populate the content index from snapshot JSON
 *   <li>Notify the CommandManager service of successful updates
 * </ul>
 *
 * The class is designed to be testable by injecting all external dependencies.
 */
public class SnapshotHelper {

    private static final Logger log = LogManager.getLogger(SnapshotHelper.class);

    private final Environment environment;
    private final ContextIndex contextIndex;
    private final ContentIndex contentIndex;
    private final CTIClient ctiClient;
    private final CommandManagerClient commandClient;
    private final PrivilegedRunner privilegedRunner;
    private final Unzipper unzipper;

    /**
     * Constructs a new SnapshotHelper with the required collaborators.
     *
     * @param environment OpenSearch environment for path resolution
     * @param contextIndex Index abstraction for context-related metadata
     * @param contentIndex Index abstraction for CVE content
     * @param ctiClient Client to communicate with CTI service
     * @param commandClient Client to post commands to the CommandManager
     * @param privilegedRunner Abstraction to run privileged code
     * @param unzipper Unzip utility for snapshot files
     */
    public SnapshotHelper(
            Environment environment,
            ContextIndex contextIndex,
            ContentIndex contentIndex,
            CTIClient ctiClient,
            CommandManagerClient commandClient,
            PrivilegedRunner privilegedRunner,
            Unzipper unzipper) {
        this.environment = environment;
        this.contextIndex = contextIndex;
        this.contentIndex = contentIndex;
        this.ctiClient = ctiClient;
        this.commandClient = commandClient;
        this.privilegedRunner = privilegedRunner;
        this.unzipper = unzipper;
    }

    /**
     * Initializes the CVE index by:
     *
     * <ol>
     *   <li>Indexing the current consumer context from the CTI API
     *   <li>Downloading and indexing snapshot JSON if required
     * </ol>
     */
    public void initializeCVEIndex() {
        try {
            updateContextIndex();
            indexSnapshot();
        } catch (IOException e) {
            log.error("Failed to initialize CVE Index from snapshot: {}", e.getMessage());
        }
    }

    /**
     * Updates the wazuh-context index with consumer metadata retrieved from the CTI API.
     *
     * @throws IOException if the indexing operation fails or returns an unexpected result
     */
    public void updateContextIndex() throws IOException {
        ConsumerInfo consumerInfo = getConsumerInfo();

        DocWriteResponse.Result result = contextIndex.index(consumerInfo).getResult();

        if (Objects.requireNonNull(result) == DocWriteResponse.Result.CREATED
                || result == DocWriteResponse.Result.UPDATED) {
            log.info("Successfully initialized consumer [{}]", consumerInfo.getContext());
        } else {
            throw new IOException(
                    String.format(
                            Locale.ROOT,
                            "Consumer indexing operation returned with unexpected result [%s]",
                            result));
        }
    }

    /**
     * Downloads, extracts, and indexes the snapshot JSON file. Only performs this operation if the
     * context offset is 0.
     */
    private void indexSnapshot() {
        if (contextIndex.getOffset() > 0) {
            return;
        }

        privilegedRunner.run(
                () -> {
                    Path snapshotZip = ctiClient.download(contextIndex.getLastSnapshotLink(), environment);
                    Path outputDir = environment.resolveRepoFile("");

                    List<Path> snapshotJson = new ArrayList<>();
                    try {
                        unzipper.unzip(snapshotZip, outputDir);

                        try (DirectoryStream<Path> stream =
                                Files.newDirectoryStream(
                                        outputDir,
                                        String.format(
                                                Locale.ROOT,
                                                "%s_%s_*.json",
                                                PluginSettings.CONTEXT_ID,
                                                PluginSettings.CONSUMER_ID))) {
                            for (Path path : stream) {
                                snapshotJson.add(path);
                            }
                        }

                        postUpdateCommand();
                        contentIndex.fromSnapshot(snapshotJson.get(0).toString());

                        Files.deleteIfExists(snapshotZip);
                        Files.deleteIfExists(snapshotJson.get(0));
                    } catch (IOException | NullPointerException e) {
                        log.error("Failed to index snapshot: {}", e.getMessage());
                    }
                });
    }

    /**
     * Posts an update command to the CommandManager service with the current context offset as
     * payload.
     */
    protected void postUpdateCommand() {
        commandClient.postCommand(Command.create(contextIndex.getLastOffset().toString()));
    }

    /**
     * Retrieves consumer metadata from the CTI API in a privileged context.
     *
     * @return the current {@link ConsumerInfo} from the CTI API
     */
    protected ConsumerInfo getConsumerInfo() {
        return privilegedRunner.supply(ctiClient::getCatalog);
    }

    /**
     * Functional interface to encapsulate privileged operations. Useful for abstracting {@code
     * doPrivileged} logic for mocking in tests.
     */
    public interface PrivilegedRunner {
        /**
         * Runs a privileged action with no return value.
         *
         * @param runnable the operation to execute
         */
        void run(Runnable runnable);

        /**
         * Executes a privileged action and returns its result.
         *
         * @param supplier the operation to evaluate
         * @param <T> the return type
         * @return the result of the operation
         */
        <T> T supply(SupplierWithException<T> supplier);
    }

    /**
     * Functional interface representing a supplier that may throw an exception.
     *
     * @param <T> the return type
     */
    public interface SupplierWithException<T> {
        T get() throws RuntimeException;
    }

    /**
     * Interface to abstract the unzip functionality. This allows mocking unzip operations in unit
     * tests.
     */
    public interface Unzipper {
        /**
         * Unzips a file to a specified directory.
         *
         * @param zipFile the zip archive to extract
         * @param outputDir the target directory for extracted files
         * @throws IOException if extraction fails
         */
        void unzip(Path zipFile, Path outputDir) throws IOException;
    }
}
