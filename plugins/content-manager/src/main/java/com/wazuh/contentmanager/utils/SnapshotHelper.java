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
import java.util.Objects;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.settings.PluginSettings;

/** Helper class to handle indexing of snapshots */
public final class SnapshotHelper {

    private static final Logger log = LogManager.getLogger(SnapshotHelper.class);

    /**
     * Download, decompress and index a CTI snapshot
     *
     * @param environment necessary for file handling
     * @param contextIndex Needed for interactions with the context index
     * @param contentIndex Used to interact with the content index
     */
    public static void indexSnapshot(
            Environment environment, ContextIndex contextIndex, ContentIndex contentIndex) {
        Privileged.doPrivilegedRequest(
                () -> {
                    Path snapshotZip =
                            CTIClient.getInstance().download(contextIndex.getLastSnapshotLink(), environment);
                    Path outputDir = environment.resolveRepoFile("");

                    List<String> snapshotJson = new ArrayList<>();
                    try (DirectoryStream<Path> stream =
                            Files.newDirectoryStream(
                                    outputDir,
                                    String.format(
                                            "%s_%s_*.json", PluginSettings.CONTEXT_ID, PluginSettings.CONSUMER_ID))) {
                        Unzip.unzip(snapshotZip, outputDir);
                        for (Path path : stream) {
                            snapshotJson.add(path.toString());
                        }
                    } catch (IOException e) {
                        log.error("Failed to find uncompressed JSON snapshot: {}", e.getMessage());
                    }
                    contentIndex.fromSnapshot(snapshotJson.get(0));
                    return null;
                });
    }

    /**
     * Updates the context index with data from the CTI API
     *
     * @param contextIndex the object in charge of indexing the data
     */
    public static void updateContextIndex(ContextIndex contextIndex) {
        ConsumerInfo consumerInfo =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());

        DocWriteResponse.Result result = contextIndex.index(consumerInfo).getResult();

        if (Objects.requireNonNull(result) == DocWriteResponse.Result.CREATED
                || Objects.requireNonNull(result) == DocWriteResponse.Result.UPDATED) {
            log.info("Successfully initialized consumer [{}]", consumerInfo.getContext());
        } else {
            log.info("Consumer indexing operation returned with unexpected result [{}]", result);
        }
    }
}
