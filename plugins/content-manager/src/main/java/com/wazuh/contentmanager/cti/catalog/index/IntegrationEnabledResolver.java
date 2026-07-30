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
package com.wazuh.contentmanager.cti.catalog.index;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Resolution rules for the three enabled fields carried by a standard integration document.
 *
 * <ul>
 *   <li>{@code cti_enabled} — the state published by CTI.
 *   <li>{@code user_enabled} — the user's explicit choice. <b>Absent means the user never
 *       decided</b>; an explicit {@code false} is a real decision, so presence (never truthiness)
 *       is what these methods test.
 *   <li>{@code enabled} — the effective state, resolved from the two above. The only one existing
 *       consumers read.
 * </ul>
 *
 * <p>Stateless and IO-free on purpose: callers sit on ingest paths shared by every resource type,
 * so the rules live here rather than being spread across those paths.
 */
public final class IntegrationEnabledResolver {

    private IntegrationEnabledResolver() {}

    /**
     * @param document the {@code document} node of an integration, may be {@code null}.
     * @return {@code true} when the user has explicitly set a value.
     */
    public static boolean hasUserOverride(JsonNode document) {
        return isPresent(document, Constants.KEY_USER_ENABLED);
    }

    /**
     * Re-attaches a previously stored user override onto a document rebuilt from CTI content.
     *
     * @param target the {@code document} node to update in place.
     * @param previousOverride the stored override, or {@code null} when there was none.
     */
    public static void carryOverUserOverride(ObjectNode target, Boolean previousOverride) {
        if (target == null || previousOverride == null) {
            return;
        }
        target.put(Constants.KEY_USER_ENABLED, previousOverride.booleanValue());
    }

    /**
     * Applies the resolution rule in place: the user's choice wins when present, otherwise CTI's
     * published value is used.
     *
     * <p>When neither field is present the current {@code enabled} is left untouched. That is the
     * transition path: until CTI publishes {@code cti_enabled} it still writes {@code enabled}
     * directly, and overwriting it would discard the value that just arrived.
     *
     * <p>Idempotent, so it is safe to call on every ingest as a self-healing step.
     *
     * @param document the {@code document} node to update in place.
     */
    public static void resolve(ObjectNode document) {
        if (document == null) {
            return;
        }
        if (hasUserOverride(document)) {
            document.put(Constants.KEY_ENABLED, document.get(Constants.KEY_USER_ENABLED).asBoolean());
            return;
        }
        if (isPresent(document, Constants.KEY_CTI_ENABLED)) {
            document.put(Constants.KEY_ENABLED, document.get(Constants.KEY_CTI_ENABLED).asBoolean());
        }
    }

    private static boolean isPresent(JsonNode document, String field) {
        return document != null && document.has(field) && !document.get(field).isNull();
    }
}
