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

import java.util.List;

/**
 * Initializes the <code>.wazuh-ai-assistant-settings</code> index, which holds the AI providers
 * configuration (including their API keys) and the assistant-wide settings.
 *
 * <p>The index is readable by administrators only. OpenSearch Security has no deny rules, so the
 * restriction is a Document Level Security query in the {@code wazuh_ai_assistant_settings} role
 * (defined in the wazuh-indexer repository): it is mapped to every user and only returns the
 * documents whose {@link #VISIBILITY_FIELD} lists one of the reader's own backend roles ({@code
 * ${user.roles}} expands to backend roles, not to mapped security roles).
 *
 * <p>Clients never write that field. {@link AIAssistantSettingsVisibilityFilter} sets it on every
 * document reaching this index. A document that somehow carries no value is visible to nobody, so
 * the failure mode is closed.
 */
public class AIAssistantSettingsIndex extends StateIndex {

    /** Index name for the AI assistant providers and settings. */
    public static final String INDEX_NAME = ".wazuh-ai-assistant-settings";

    /** Field holding the backend roles allowed to read a document. */
    public static final String VISIBILITY_FIELD = "visible_to";

    /**
     * Backend roles allowed to read the index: 'admin' backs both all_access and wazuh_admin, and
     * 'wazuh-admin' is carried by the wazuh-admin internal user, which is mapped by username. Any
     * additional administrator must hold one of these to read the index.
     */
    public static final List<String> VISIBLE_TO = List.of("admin", "wazuh-admin");

    /**
     * Constructor.
     *
     * @param index index name.
     * @param template index template name.
     */
    public AIAssistantSettingsIndex(String index, String template) {
        super(index, template);
    }
}
