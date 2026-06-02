/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.cluster.ClusterChangedEvent;
import org.opensearch.cluster.ClusterStateListener;
import org.opensearch.gateway.GatewayService;
import org.opensearch.threadpool.ThreadPool;

import java.util.List;

/**
 * Cluster-state listener that registers rollover-created backing indices with ISM. Closes the gap
 * between the initial enrolment done by {@link IsmManagedIndex#initialize()} (which only fires at
 * cluster startup) and the run-time backing indices ISM creates via {@code attempt_rollover}.
 *
 * <p>On every cluster state change, scans {@code event.indicesCreated()}; for each new index that
 * one of the registered {@link IsmManagedIndex} instances claims (see {@link
 * IsmManagedIndex#ownsBackingIndex}), invokes {@link IsmManagedIndex#registerWithISM()} to write a
 * {@code ManagedIndexConfig} doc for it.
 *
 * <p>Registered once in {@code SetupPlugin.createComponents()} so it survives cluster-manager
 * failover; gated internally on {@code event.localNodeClusterManager()} so non-CM nodes do nothing.
 */
public class IsmRolloverListener implements ClusterStateListener {
    private static final Logger log = LogManager.getLogger(IsmRolloverListener.class);

    private final List<IsmManagedIndex> managed;
    private final ThreadPool threadPool;

    /**
     * Constructor.
     *
     * @param managed the {@link IsmManagedIndex} instances whose rollover targets should be enrolled.
     * @param threadPool node thread pool — used to dispatch {@code registerWithISM()} off the
     *     cluster-state applier thread (blocking operations there trigger an assertion error).
     */
    public IsmRolloverListener(List<IsmManagedIndex> managed, ThreadPool threadPool) {
        this.managed = managed;
        this.threadPool = threadPool;
    }

    @Override
    public void clusterChanged(ClusterChangedEvent event) {
        if (!event.localNodeClusterManager()) {
            return;
        }
        if (event.state().blocks().hasGlobalBlock(GatewayService.STATE_NOT_RECOVERED_BLOCK)) {
            return;
        }
        if (event.indicesCreated().isEmpty()) {
            return;
        }

        for (String newIndex : event.indicesCreated()) {
            for (IsmManagedIndex owner : this.managed) {
                if (owner.ownsBackingIndex(newIndex, event.state())) {
                    log.debug(
                            "Detected new backing index [{}] for managed entity [{}]; triggering ISM registration.",
                            newIndex,
                            owner.index);
                    // registerWithISM does blocking client.get/index calls which are forbidden on
                    // the cluster-state applier thread. Dispatch to the generic pool.
                    this.threadPool.generic().execute(owner::registerWithISM);
                    break;
                }
            }
        }
    }
}
