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
package com.wazuh.contentmanager.action;

import org.opensearch.action.ActionType;

/**
 * Nodes-level action that tells every node to reload the STANDARD space into its own local Engine.
 *
 * <p>Fired by the cluster manager after a content-changing sync so that all nodes converge
 * promptly, not only when they next happen to receive an unrelated cluster-state event. Each node's
 * handler delegates to the same hash-gated loader used by the per-node cluster-state listener, so a
 * redundant broadcast is a cheap no-op.
 */
public class ReloadEngineContentAction extends ActionType<ReloadEngineContentResponse> {
    public static final String NAME = "cluster:admin/content_manager/engine/reload";
    public static final ReloadEngineContentAction INSTANCE = new ReloadEngineContentAction();

    public ReloadEngineContentAction() {
        super(NAME, ReloadEngineContentResponse::new);
    }
}
