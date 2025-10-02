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
package com.wazuh.setup;

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

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import com.wazuh.setup.index.Index;
import com.wazuh.setup.index.IndexStateManagement;
import com.wazuh.setup.index.StateIndex;
import com.wazuh.setup.index.StreamIndex;
import com.wazuh.setup.settings.PluginSettings;
import com.wazuh.setup.utils.IndexUtils;

/**
 * Main class of the Indexer Setup plugin. This plugin is responsible for the creation of the index
 * templates and indices required by Wazuh to work properly.
 */
public class SetupPlugin extends Plugin implements ClusterPlugin {

    private final List<Index> indices = new ArrayList<>();

    /** Default constructor */
    public SetupPlugin() {}

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
        // spotless:off
        // ISM index
        this.indices.add(new IndexStateManagement(".opendistro-ism-config", "opendistro-ism-config"));
        // Stream indices
        this.indices.add(new StreamIndex("wazuh-alerts-5.x-000001", "index-template-alerts", "wazuh-alerts"));
        this.indices.add(new StreamIndex("wazuh-archives-5.x-000001", "index-template-archives", "wazuh-archives"));
        // Decoder indices
        // this.indices.add(new StreamIndex(
        //     "wazuh-events-5.x-<integration-name>-000001",
        //     "index-template-<integration-name>",
        //     "wazuh-events-<integration-name>"
        // ));
        // TODO transform into loop
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-amazon-security-lake-000001",
            "index-template-amazon-security-lake",
            "wazuh-events-amazon-security-lake"
        ));
        this.indices.add(new StreamIndex(
                 "wazuh-events-5.x-apache_tomcat-000001",
                 "index-template-apache_tomcat",
                 "wazuh-events-apache_tomcat"
             ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-audit-000001",
            "index-template-audit",
            "wazuh-events-audit"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-azure-000001",
            "index-template-azure",
            "wazuh-events-azure"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-azure-app-service-000001",
            "index-template-azure-app-service",
            "wazuh-events-azure-app-service"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-azure-metrics-000001",
            "index-template-azure-metrics",
            "wazuh-events-azure-metrics"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-checkpoint-000001",
            "index-template-checkpoint",
            "wazuh-events-checkpoint"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-cisco_umbrella-000001",
            "index-template-cisco_umbrella",
            "wazuh-events-cisco_umbrella"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-cisco-asa-000001",
            "index-template-cisco-asa",
            "wazuh-events-cisco-asa"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-f5-bigip-000001",
            "index-template-f5-bigip",
            "wazuh-events-f5-bigip"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-fortinet-000001",
            "index-template-fortinet",
            "wazuh-events-fortinet"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-gcp-000001",
            "index-template-gcp",
            "wazuh-events-gcp"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-iis-000001",
            "index-template-iis",
            "wazuh-events-iis"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-iptables-000001",
            "index-template-iptables",
            "wazuh-events-iptables"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-microsoft-dhcp-000001",
            "index-template-microsoft-dhcp",
            "wazuh-events-microsoft-dhcp"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-microsoft-dnsserver-000001",
            "index-template-microsoft-dnsserver",
            "wazuh-events-microsoft-dnsserver"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-microsoft-exchange-server-000001",
            "index-template-microsoft-exchange-server",
            "wazuh-events-microsoft-exchange-server"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-modsec-000001",
            "index-template-modsec",
            "wazuh-events-modsec"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-oracle_weblogic-000001",
            "index-template-oracle_weblogic",
            "wazuh-events-oracle_weblogic"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-pfsense-000001",
            "index-template-pfsense",
            "wazuh-events-pfsense"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-snort-000001",
            "index-template-snort",
            "wazuh-events-snort"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-spring_boot-000001",
            "index-template-spring_boot",
            "wazuh-events-spring_boot"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-squid-000001",
            "index-template-squid",
            "wazuh-events-squid"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-suricata-000001",
            "index-template-suricata",
            "wazuh-events-suricata"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-unifiedlogs-000001",
            "index-template-unifiedlogs",
            "wazuh-events-unifiedlogs"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-websphere-000001",
            "index-template-websphere",
            "wazuh-events-websphere"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-windows-000001",
            "index-template-windows",
            "wazuh-events-windows"
        ));
        this.indices.add(new StreamIndex(
            "wazuh-events-5.x-zeek-000001",
            "index-template-zeek",
            "wazuh-events-zeek"
        ));

        // State indices
        this.indices.add(new StateIndex("wazuh-states-sca", "index-template-sca"));
        this.indices.add(new StateIndex("wazuh-states-fim-files", "index-template-fim-files"));
        this.indices.add(new StateIndex("wazuh-states-fim-registry-keys", "index-template-fim-registry-keys"));
        this.indices.add(new StateIndex("wazuh-states-fim-registry-values", "index-template-fim-registry-values"));
        this.indices.add(new StateIndex("wazuh-states-inventory-browser-extensions", "index-template-browser-extensions"));
        this.indices.add(new StateIndex("wazuh-states-inventory-groups", "index-template-groups"));
        this.indices.add(new StateIndex("wazuh-states-inventory-hardware", "index-template-hardware"));
        this.indices.add(new StateIndex("wazuh-states-inventory-hotfixes", "index-template-hotfixes"));
        this.indices.add(new StateIndex("wazuh-states-inventory-interfaces", "index-template-interfaces"));
        this.indices.add(new StateIndex("wazuh-monitoring", "index-template-monitoring"));
        this.indices.add(new StateIndex("wazuh-states-inventory-networks", "index-template-networks"));
        this.indices.add(new StateIndex("wazuh-states-inventory-packages", "index-template-packages"));
        this.indices.add(new StateIndex("wazuh-states-inventory-ports", "index-template-ports"));
        this.indices.add(new StateIndex("wazuh-states-inventory-processes", "index-template-processes"));
        this.indices.add(new StateIndex("wazuh-states-inventory-protocols", "index-template-protocols"));
        this.indices.add(new StateIndex("wazuh-states-inventory-services", "index-template-services"));
        this.indices.add(new StateIndex("wazuh-states-inventory-system", "index-template-system"));
        this.indices.add(new StateIndex("wazuh-states-inventory-users", "index-template-users"));
        this.indices.add(new StateIndex("wazuh-states-vulnerabilities", "index-template-vulnerabilities"));
        this.indices.add(new StateIndex("wazuh-statistics", "index-template-statistics"));
        // spotless:on

        // Inject dependencies
        IndexUtils utils = new IndexUtils();
        this.indices.forEach(
                index -> {
                    index.setClient(client);
                    index.setClusterService(clusterService);
                    index.setIndexUtils(utils);
                });

        return Collections.emptyList();
    }

    @Override
    public void onNodeStarted(DiscoveryNode localNode) {
        // Initialize the indices only if this node is the cluster manager node.
        if (localNode.isClusterManagerNode()) {
            this.indices.forEach(Index::initialize);
        }
    }

    @Override
    public List<Setting<?>> getSettings() {
        return List.of(PluginSettings.TIMEOUT, PluginSettings.BACKOFF);
    }
}
