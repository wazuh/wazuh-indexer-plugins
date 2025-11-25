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
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.transport.client.Client;
import org.opensearch.cluster.metadata.IndexNameExpressionResolver;
import org.opensearch.cluster.node.DiscoveryNode;
import org.opensearch.cluster.service.ClusterService;
import org.opensearch.common.settings.*;
import org.opensearch.core.common.io.stream.NamedWriteableRegistry;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.env.Environment;
import org.opensearch.env.NodeEnvironment;
import org.opensearch.plugins.ClusterPlugin;
import org.opensearch.plugins.ActionPlugin;
import org.opensearch.plugins.Plugin;
import org.opensearch.repositories.RepositoriesService;
import org.opensearch.script.ScriptService;
import org.opensearch.threadpool.ThreadPool;
import org.opensearch.watcher.ResourceWatcherService;

import java.util.*;
import java.util.concurrent.Semaphore;
import java.util.function.Supplier;

import com.wazuh.contentmanager.index.ContentIndex;
import com.wazuh.contentmanager.index.ConsumersIndex;
import com.wazuh.contentmanager.rest.services.RestDeleteSubscriptionAction;
import com.wazuh.contentmanager.rest.services.RestGetSubscriptionAction;
import com.wazuh.contentmanager.rest.services.RestPostSubscriptionAction;
import com.wazuh.contentmanager.rest.services.RestPostUpdateAction;
import com.wazuh.contentmanager.services.ContentManagerService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Privileged;
import com.wazuh.contentmanager.utils.SnapshotManager;
import org.opensearch.rest.RestHandler;
import java.util.List;
import java.util.Collections;

/** Main class of the Content Manager Plugin */
public class ContentManagerPlugin extends Plugin implements ClusterPlugin, ActionPlugin {
    private static final Logger log = LogManager.getLogger(ContentManagerPlugin.class);
    /**
     * Semaphore to ensure the context index creation is only triggered once.
     */
    private static final Semaphore indexCreationSemaphore = new Semaphore(1);
    private ConsumersIndex consumersIndex;
    private ContentIndex contentIndex;
    private SnapshotManager snapshotManager;
    private ThreadPool threadPool;
    private ClusterService clusterService;
    private ContentManagerService contentManagerService;
    private CtiConsole ctiConsole;

    // Rest API endpoints
    public static final String PLUGINS_BASE_URI = "/_plugins/content-manager";
    public static final String SUBSCRIPTION_URI = PLUGINS_BASE_URI + "/subscription";
    public static final String UPDATE_URI = PLUGINS_BASE_URI + "/update";

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
        this.consumersIndex = new ConsumersIndex(client);
        this.contentIndex = new ContentIndex(client);
        this.snapshotManager =
            new SnapshotManager(environment, this.consumersIndex, this.contentIndex, new Privileged());
        this.contentManagerService = new ContentManagerService(this.threadPool);

        // Content Manager 5.0
        this.ctiConsole = new CtiConsole();
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
            this.start();
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

    public List<RestHandler> getRestHandlers(
        Settings settings,
        org.opensearch.rest.RestController restController,
        org.opensearch.common.settings.ClusterSettings clusterSettings,
        org.opensearch.common.settings.IndexScopedSettings indexScopedSettings,
        org.opensearch.common.settings.SettingsFilter settingsFilter,
        org.opensearch.cluster.metadata.IndexNameExpressionResolver indexNameExpressionResolver,
        java.util.function.Supplier<org.opensearch.cluster.node.DiscoveryNodes> nodesInCluster) {
        return List.of(
            new RestGetSubscriptionAction(this.ctiConsole),
            new RestPostSubscriptionAction(this.ctiConsole),
            new RestDeleteSubscriptionAction(this.ctiConsole),
            new RestPostUpdateAction(contentManagerService)
        );
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
                        if (indexCreationSemaphore.tryAcquire()) {
                            try {
                                this.consumersIndex.createIndex();
                            } catch (Exception e) {
                                indexCreationSemaphore.release();
                                log.error("Failed to create {} index, due to: {}", ConsumersIndex.INDEX_NAME, e.getMessage(), e);
                            }
                        } else {
                            log.debug("{} index creation already triggered", ConsumersIndex.INDEX_NAME);
                        }
                        // TODO: Once initialize method is adapted to the new design, uncomment the following line
                        //this.snapshotManager.initialize();
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
