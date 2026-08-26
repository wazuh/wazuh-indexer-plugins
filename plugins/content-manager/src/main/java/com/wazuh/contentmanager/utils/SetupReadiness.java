/*
 * Copyright (C) 2026, Wazuh Inc.
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
import org.opensearch.action.admin.cluster.node.info.NodeInfo;
import org.opensearch.action.admin.cluster.node.info.NodesInfoRequest;
import org.opensearch.action.admin.cluster.node.info.NodesInfoResponse;
import org.opensearch.action.admin.cluster.node.info.PluginsAndModules;
import org.opensearch.action.get.GetResponse;
import org.opensearch.common.unit.TimeValue;
import org.opensearch.plugins.PluginInfo;
import org.opensearch.transport.client.Client;

import java.util.Map;
import java.util.concurrent.TimeUnit;

import com.wazuh.contentmanager.settings.PluginSettings;

/**
 * Waits for the Setup plugin to finish initializing.
 *
 * <p>The Setup plugin owns the index topology this plugin writes into: the {@code
 * wazuh-threatintel-*} content indices, each created as {@code <name>-a} with the public alias
 * {@code <name>} pointing at it. Anything that provisions or writes to those indices has to wait
 * for that to be in place, otherwise it races the Setup plugin and can create a concrete index
 * under the alias name — auto-created with dynamic mappings, so its fields cannot be aggregated or
 * sorted on (see issue #1476).
 */
public class SetupReadiness {

    private static final Logger log = LogManager.getLogger(SetupReadiness.class);

    /** Name the Setup plugin registers itself under, as declared in its {@code build.gradle}. */
    private static final String SETUP_PLUGIN_NAME = "wazuh-indexer-setup";

    private final Client client;

    /**
     * Memoised answer to {@link #isSetupPluginInstalled()}. Plugins are loaded when the node starts
     * and cannot be added or removed without a restart, so the answer cannot change while this node
     * lives. Only a definitive answer is cached: a failed lookup stays uncached so a transient error
     * does not pin the result for the rest of the node's lifetime.
     */
    private volatile Boolean setupPluginInstalled;

    /**
     * Constructor.
     *
     * @param client The OpenSearch client used to read the readiness marker.
     */
    public SetupReadiness(Client client) {
        this.client = client;
    }

    /**
     * Blocks until the Setup plugin reports its initialization as {@value
     * Constants#SETUP_STATUS_READY} via the {@value Constants#SETUP_STATUS_DOC_ID} marker document in
     * the {@value Constants#INDEX_SETUP_STATUS} index. Retries up to {@link
     * PluginSettings#SETUP_WAIT_MAX_RETRIES} times with exponential backoff starting at {@link
     * PluginSettings#SETUP_WAIT_BACKOFF_BASE_SECONDS} before giving up (defaults: 20s, 40s, 80s, 160s
     * = 300s / 5 min worst case). If the marker already reports {@value
     * Constants#SETUP_STATUS_FAILED}, returns immediately without retrying — a failed Setup boot will
     * not fix itself within the same boot.
     *
     * @return true if the Setup plugin reported readiness, false otherwise.
     */
    public boolean awaitReady() {
        if (!this.isSetupPluginInstalled()) {
            log.info(Constants.I_LOG_SETUP_PLUGIN_ABSENT);
            return false;
        }
        int maxRetries = PluginSettings.getInstance().getSetupWaitMaxRetries();
        int backoffBaseSeconds = PluginSettings.getInstance().getSetupWaitBackoffBaseSeconds();
        for (int attempt = 0; ; attempt++) {
            SetupStatus status = this.readSetupStatus();
            if (status == SetupStatus.READY) {
                return true;
            }
            if (status == SetupStatus.FAILED) {
                log.error(Constants.E_LOG_SETUP_INIT_FAILED);
                return false;
            }
            if (attempt >= maxRetries) {
                return false;
            }
            long delaySeconds = backoffBaseSeconds * (1L << attempt);
            log.info(Constants.I_LOG_SETUP_NOT_READY_RETRYING, delaySeconds, attempt + 1, maxRetries);
            try {
                this.sleepSeconds(delaySeconds);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
    }

    /**
     * Returns whether the Setup plugin is installed on any node of the cluster.
     *
     * <p>Without this check {@link #awaitReady()} would burn its whole backoff schedule waiting for a
     * marker that is never going to be written, delaying everything behind it by five minutes on
     * exactly the deployment the caller's fallback exists to serve. A failure to read the plugin list
     * is reported as "installed" so a transient error makes the caller wait rather than skip the wait
     * and race the Setup plugin.
     *
     * @return true if the Setup plugin is installed, or if the plugin list could not be read.
     */
    public boolean isSetupPluginInstalled() {
        Boolean cached = this.setupPluginInstalled;
        if (cached != null) {
            return cached;
        }
        try {
            NodesInfoResponse response =
                    this.client
                            .admin()
                            .cluster()
                            .prepareNodesInfo()
                            .clear()
                            .addMetric(NodesInfoRequest.Metric.PLUGINS.metricName())
                            .get(TimeValue.timeValueSeconds(PluginSettings.getInstance().getClientTimeout()));
            for (NodeInfo node : response.getNodes()) {
                PluginsAndModules plugins = node.getInfo(PluginsAndModules.class);
                if (plugins == null) {
                    continue;
                }
                for (PluginInfo plugin : plugins.getPluginInfos()) {
                    if (SETUP_PLUGIN_NAME.equals(plugin.getName())) {
                        this.setupPluginInstalled = true;
                        return true;
                    }
                }
            }
            this.setupPluginInstalled = false;
            return false;
        } catch (Exception e) {
            log.debug(Constants.D_LOG_SETUP_PLUGIN_LOOKUP_FAILED, e.getMessage());
            return true;
        }
    }

    /**
     * Sleeps for the given number of seconds. Extracted from {@link #awaitReady()} so tests can stub
     * it out and exercise the full retry loop without actually blocking for its real duration.
     *
     * @param seconds The number of seconds to sleep.
     * @throws InterruptedException if the thread is interrupted while sleeping.
     */
    void sleepSeconds(long seconds) throws InterruptedException {
        TimeUnit.SECONDS.sleep(seconds);
    }

    /** The three states the Setup plugin's readiness marker can report. */
    private enum SetupStatus {
        RUNNING,
        READY,
        FAILED
    }

    /**
     * Reads the Setup plugin's readiness marker. Any failure (index not created yet, cluster not
     * ready) is treated as {@link SetupStatus#RUNNING} so the caller retries.
     *
     * @return the marker's current {@link SetupStatus}.
     */
    private SetupStatus readSetupStatus() {
        try {
            GetResponse response =
                    this.client.prepareGet(Constants.INDEX_SETUP_STATUS, Constants.SETUP_STATUS_DOC_ID).get();
            if (!response.isExists()) {
                return SetupStatus.RUNNING;
            }
            Map<String, Object> source = response.getSourceAsMap();
            Object value = source != null ? source.get(Constants.KEY_STATUS) : null;
            if (Constants.SETUP_STATUS_READY.equals(value)) {
                return SetupStatus.READY;
            }
            if (Constants.SETUP_STATUS_FAILED.equals(value)) {
                return SetupStatus.FAILED;
            }
            return SetupStatus.RUNNING;
        } catch (Exception e) {
            log.debug(Constants.D_LOG_SETUP_STATUS_READ_FAILED, e.getMessage());
            return SetupStatus.RUNNING;
        }
    }
}
