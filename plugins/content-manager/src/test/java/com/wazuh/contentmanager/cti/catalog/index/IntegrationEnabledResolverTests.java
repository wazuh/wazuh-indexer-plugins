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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;

import com.wazuh.contentmanager.utils.Constants;

public class IntegrationEnabledResolverTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private ObjectNode document(Boolean enabled, Boolean userEnabled, Boolean ctiEnabled) {
        ObjectNode node = MAPPER.createObjectNode();
        if (enabled != null) node.put(Constants.KEY_ENABLED, enabled);
        if (userEnabled != null) node.put(Constants.KEY_USER_ENABLED, userEnabled);
        if (ctiEnabled != null) node.put(Constants.KEY_CTI_ENABLED, ctiEnabled);
        return node;
    }

    public void testHasUserOverrideFalseWhenAbsent() {
        assertFalse(IntegrationEnabledResolver.hasUserOverride(document(true, null, true)));
    }

    /** A false override is a real override: presence, not truthiness, decides. */
    public void testHasUserOverrideTrueWhenExplicitlyFalse() {
        assertTrue(IntegrationEnabledResolver.hasUserOverride(document(true, false, true)));
    }

    public void testHasUserOverrideFalseWhenNullNode() {
        ObjectNode node = document(true, null, true);
        node.putNull(Constants.KEY_USER_ENABLED);
        assertFalse(IntegrationEnabledResolver.hasUserOverride(node));
    }

    public void testHasUserOverrideFalseWhenDocumentIsNull() {
        assertFalse(IntegrationEnabledResolver.hasUserOverride(null));
    }

    public void testResolveAppliesUserOverrideOverCtiValue() {
        ObjectNode node = document(true, false, true);
        IntegrationEnabledResolver.resolve(node);
        assertFalse(node.get(Constants.KEY_ENABLED).asBoolean());
    }

    public void testResolveFallsBackToCtiValue() {
        ObjectNode node = document(true, null, false);
        IntegrationEnabledResolver.resolve(node);
        assertFalse(node.get(Constants.KEY_ENABLED).asBoolean());
    }

    /** Transition path: CTI has not shipped cti_enabled yet, so enabled must be left alone. */
    public void testResolveLeavesEnabledUntouchedWhenNeitherFieldIsPresent() {
        ObjectNode node = document(true, null, null);
        IntegrationEnabledResolver.resolve(node);
        assertTrue(node.get(Constants.KEY_ENABLED).asBoolean());
    }

    /** Transition path with an override: the user still wins. */
    public void testResolveAppliesUserOverrideWithoutCtiValue() {
        ObjectNode node = document(false, true, null);
        IntegrationEnabledResolver.resolve(node);
        assertTrue(node.get(Constants.KEY_ENABLED).asBoolean());
    }

    public void testResolveIsIdempotent() {
        ObjectNode node = document(true, false, true);
        IntegrationEnabledResolver.resolve(node);
        IntegrationEnabledResolver.resolve(node);
        assertFalse(node.get(Constants.KEY_ENABLED).asBoolean());
    }

    public void testCarryOverUserOverrideAppliesPreviousValue() {
        ObjectNode node = document(true, null, true);
        IntegrationEnabledResolver.carryOverUserOverride(node, Boolean.FALSE);
        assertTrue(node.has(Constants.KEY_USER_ENABLED));
        assertFalse(node.get(Constants.KEY_USER_ENABLED).asBoolean());
    }

    public void testCarryOverUserOverrideNoOpWhenPreviousIsNull() {
        ObjectNode node = document(true, null, true);
        IntegrationEnabledResolver.carryOverUserOverride(node, null);
        assertFalse(node.has(Constants.KEY_USER_ENABLED));
    }
}
