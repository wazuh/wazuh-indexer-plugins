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
package com.wazuh.setup.action;

import org.opensearch.action.ActionType;

/**
 * Transport action for every write to the caller's own AI assistant sessions — create, replace,
 * rename or delete, selected by {@link PutAiAssistantSessionRequest.Operation}. Its {@link #NAME}
 * doubles as the cluster permission enforced by the security plugin.
 *
 * <p>One action serves all four routes because all four are writes; there is no read counterpart.
 * Listing sessions and reading a transcript stay direct index queries, scoped by the {@code
 * wazuh_ai_assistant} role's document-level security filter, which is sound on the read path — it
 * is writes that document-level security cannot scope, and that this action exists to mediate.
 *
 * <p>The {@code Put} prefix is kept even though the action also serves {@code POST}, {@code PATCH}
 * and {@code DELETE}, matching {@link PutAiAssistantSettingsAction} in the same package.
 */
public class PutAiAssistantSessionAction extends ActionType<PutAiAssistantSessionResponse> {
    /** Name of this action, and the cluster permission gating it. */
    public static final String NAME = "cluster:admin/ai_assistant/session/write";

    /** Singleton instance. */
    public static final PutAiAssistantSessionAction INSTANCE = new PutAiAssistantSessionAction();

    /** Default constructor. */
    public PutAiAssistantSessionAction() {
        super(NAME, PutAiAssistantSessionResponse::new);
    }
}
