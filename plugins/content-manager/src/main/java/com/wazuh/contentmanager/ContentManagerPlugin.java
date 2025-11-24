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

import com.wazuh.contentmanager.cti.console.CtiConsole;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.cti.console.model.Product;
import com.wazuh.contentmanager.cti.console.model.Token;
import com.wazuh.contentmanager.cti.console.service.AuthServiceImpl;
import com.wazuh.contentmanager.cti.console.service.PlansServiceImpl;
import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ContextIndex;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.SnapshotManager;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.Setting;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.transport.client.Client;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin implements ClusterPlugin {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    private ContextIndex contextIndex;
    private ContentIndex contentIndex;
    private SnapshotManager snapshotManager;
    private ThreadPool threadPool;
    private ClusterService clusterService;
    private CtiConsole ctiConsole;

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
        this.threadPool = threadPool;
        this.clusterService = clusterService;
        this.contextIndex = new ContextIndex(client);
        this.contentIndex = new ContentIndex(client);
        this.snapshotManager =
                new SnapshotManager(environment, this.contextIndex, this.contentIndex, new Privileged());
//        this.ctiConsole = new CtiConsole(new AuthServiceImpl());
        return Collections.emptyList();
    }

    /**
     * The initialization requires the existence of the {@link ContentIndex#INDEX_NAME} index. For
     * this reason, we use a ClusterStateListener to listen for the creation of this index by the
     * "setup" plugin, to then proceed with the initialization.
     *
     * @param localNode local Node info
     */
    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        // Only cluster managers are responsible for the initialization.
        if (localNode.isClusterManagerNode()) {
            if (this.clusterService.state().routingTable().hasIndex(ContentIndex.INDEX_NAME)) {
                this.start();
            }

            // To be removed once we include the Job Scheduler.
            this.clusterService.addListener(
                    event -> {
                        if (event.indicesCreated().contains(ContentIndex.INDEX_NAME)) {
                            this.start();
                        }
                    });
        }

        /*
        // Use case 1. Polling
        AuthServiceImpl authService = new AuthServiceImpl();
        this.ctiConsole = new CtiConsole();
        this.ctiConsole.setAuthService(authService);
        this.ctiConsole.onPostSubscriptionRequest();

        while (!this.ctiConsole.isTokenTaskCompleted()) {}
        if (this.ctiConsole.isTokenTaskCompleted()) {
            Token token = this.ctiConsole.getToken();

            // Use case 2. Obtain available plans
            PlansServiceImpl productsService = new PlansServiceImpl();
            List<Plan> plans = productsService.getPlans(token.getAccessToken());
            log.info("Plans: {}", plans);

            // Use case 3. Obtain resource token.
            Product vulnsPro = plans.stream()
                .filter(plan -> plan.getName().equals("Pro Plan Deluxe"))
                .toList()
                .getFirst()
                .getProducts().stream()
                .filter(product -> product.getIdentifier().equals("vulnerabilities-pro"))
                .toList()
                .getFirst();

            Token resourceToken = authService.getResourceToken(
                token.getAccessToken(),
                vulnsPro.getResource()
            );
            log.info("Resource token {}", resourceToken);
        }
        */
    }

    /**
     * Initialize. The initialization consists of:
     *
     * <pre>
     *     1. fetching the latest consumer's information from the CTI API.
     *     2. initialize from a snapshot if the local consumer does not exist, or its offset is 0.
     * </pre>
     */
    private void start() {
        try {
            this.threadPool
                    .generic()
                    .execute(
                            () -> {
                                this.contextIndex.createIndex();
                                this.snapshotManager.initialize();
                            });
        } catch (Exception e) {
            // Log or handle exception
            log.error("Error initializing snapshot helper: {}", e.getMessage(), e);
        }
    }

    @Override
    public List<Setting<?>> getSettings() {
        return Arrays.asList(
                PluginSettings.CONSUMER_ID,
                PluginSettings.CONTEXT_ID,
                PluginSettings.CLIENT_TIMEOUT,
                PluginSettings.CTI_API_URL,
                PluginSettings.CTI_CLIENT_MAX_ATTEMPTS,
                PluginSettings.CTI_CLIENT_SLEEP_TIME,
                PluginSettings.JOB_MAX_DOCS,
                PluginSettings.JOB_SCHEDULE,
                PluginSettings.MAX_CHANGES,
                PluginSettings.MAX_CONCURRENT_BULKS,
                PluginSettings.MAX_ITEMS_PER_BULK);
    }
}
