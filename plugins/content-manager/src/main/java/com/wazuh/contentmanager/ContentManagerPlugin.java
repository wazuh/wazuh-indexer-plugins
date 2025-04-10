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
package com.wazuh.contentmanager;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.action.DocWriteResponse;
import org.opensearch.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.node.DiscoveryNodes;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.rest.RestController;
import org.opensearch.rest.RestHandler;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.io.IOException;
import java.nio.file.DirectoryStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.rest.UpdaterHandler;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.Unzip;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin implements ClusterPlugin, ActionPlugin {

    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private Environment environment;

    @Override
    public Collection<Object> createComponents(
            Client client,
            ClusterService clusterService,
            ThreadPool threadPool,
            ResourceWatcherService resourceWatcherService,
            ScriptService scriptService,
            NamedXContentRegistry xContentRegistry,
            Environment environment,
            NodeEnvironment nodeEnvironment,
            NamedWriteableRegistry namedWriteableRegistry,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<RepositoriesService> repositoriesServiceSupplier) {
        PluginSettings.getInstance(environment.settings(), clusterService);
        this.contextIndex = new ContextIndex(client);
        this.contentIndex = new ContentIndex(client);
        this.environment = environment;
        return Collections.emptyList();
    }

    @Override
    public List<RestHandler> getRestHandlers(
            Settings settings,
            RestController restController,
            ClusterSettings clusterSettings,
            IndexScopedSettings indexScopedSettings,
            SettingsFilter settingsFilter,
            IndexNameExpressionResolver indexNameExpressionResolver,
            Supplier<DiscoveryNodes> nodesInCluster) {
        // Just for testing purposes
        return Collections.singletonList(new UpdaterHandler());
    }

    /**
     * Call the CTI API on startup and get the latest consumer information into an index
     *
     * @param localNode local Node info
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        ConsumerInfo consumerInfo =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());

        DocWriteResponse.Result result = this.contextIndex.index(consumerInfo).getResult();

        if (Objects.requireNonNull(result) == DocWriteResponse.Result.CREATED
                || Objects.requireNonNull(result) == DocWriteResponse.Result.UPDATED) {
            log.info("Successfully initialized consumer [{}]", consumerInfo.getContext());
        } else {
            log.info("Consumer indexing operation returned with unexpected result [{}]", result);
        }

        if (this.contextIndex.getOffset() != 0) {
            return;
        }

        Privileged.doPrivilegedRequest(
                () -> {
                    String zipFileName =
                            CTIClient.getInstance()
                                    .download(this.contextIndex.getLastSnapshotLink(), environment);
                    String snapshotZip = this.environment.resolveRepoFile(zipFileName).toString();
                    Path outputDir = this.environment.resolveRepoFile("");

                    try {
                        Unzip.unzip(snapshotZip, outputDir, this.environment);
                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }

                    List<Path> matchingFiles = new ArrayList<>();
                    try (DirectoryStream<Path> stream = Files.newDirectoryStream(outputDir, "vd_1.0.0_vd_4.8.0_*.json")) {
                        for (Path path : stream) {
                            matchingFiles.add(path);
                        }
                    } catch (IOException e) {
                        log.error("Failed to find uncompressed JSON snapshot");
                    }
                    this.contentIndex.fromSnapshot(matchingFiles.get(0).toString());
                    return null;
                });
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Collections.singletonList(PluginSettings.CTI_API_URL);
    }
}
