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
package com.wazuh.contentmanager.transport;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.action.support.ActionFilters;
import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.TransportService;
import org.opensearch.transport.client.Client;
import org.junit.Before;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.Space;
import com.wazuh.contentmanager.engine.service.EngineService;
import com.wazuh.contentmanager.settings.PluginSettings;
import com.wazuh.contentmanager.utils.Constants;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class TransportUpdateIntegrationActionTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String ID = "61dbde65-f36c-4aa0-aac2-36ac259d4dd5";

    private TransportUpdateIntegrationAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.getInstance(
                Settings.builder().put("plugins.content_manager.engine.mock", true).build());
        this.action =
                new TransportUpdateIntegrationAction(
                        mock(TransportService.class),
                        mock(ActionFilters.class),
                        mock(Client.class),
                        mock(EngineService.class));
    }

    /** Stored document as CTI published it: disabled, no user decision yet. */
    private ObjectNode storedDocument() {
        ObjectNode document = MAPPER.createObjectNode();
        document.put(Constants.KEY_ID, ID);
        document.put(Constants.KEY_ENABLED, false);
        document.put(Constants.KEY_CTI_ENABLED, false);
        document.put(Constants.KEY_MODE, "user-managed");
        document.set(Constants.KEY_METADATA, MAPPER.createObjectNode().put("title", "suricata"));

        ObjectNode wrapper = MAPPER.createObjectNode();
        wrapper.set(Constants.KEY_DOCUMENT, document);
        wrapper.set(Constants.KEY_SPACE, MAPPER.createObjectNode().put("name", "standard"));
        return wrapper;
    }

    private ContentIndex indexReturning(JsonNode stored) {
        ContentIndex index = mock(ContentIndex.class);
        when(index.getDocument(ID)).thenReturn(stored);
        return index;
    }

    /** A standard-space request carries the user's decision in user_enabled. */
    private ObjectNode request(boolean userEnabled) {
        ObjectNode node = MAPPER.createObjectNode();
        node.put(Constants.KEY_ID, ID);
        node.put(Constants.KEY_USER_ENABLED, userEnabled);
        return node;
    }

    public void testStandardPutStoresUserChoiceAndResolvesEnabled() {
        ObjectNode payload = request(true);
        assertNull(
                this.action.preserveMetadata(
                        indexReturning(storedDocument()), ID, payload, Space.STANDARD));
        assertTrue(payload.get(Constants.KEY_USER_ENABLED).asBoolean());
        assertTrue(payload.get(Constants.KEY_ENABLED).asBoolean());
    }

    /** Disabling is a decision too, and must be recorded as such. */
    public void testStandardPutStoresFalseChoice() {
        ObjectNode stored = storedDocument();
        ((ObjectNode) stored.get(Constants.KEY_DOCUMENT)).put(Constants.KEY_ENABLED, true);
        ((ObjectNode) stored.get(Constants.KEY_DOCUMENT)).put(Constants.KEY_CTI_ENABLED, true);

        ObjectNode payload = request(false);
        this.action.preserveMetadata(indexReturning(stored), ID, payload, Space.STANDARD);

        assertTrue(payload.has(Constants.KEY_USER_ENABLED));
        assertFalse(payload.get(Constants.KEY_USER_ENABLED).asBoolean());
        assertFalse(payload.get(Constants.KEY_ENABLED).asBoolean());
    }

    public void testStandardPutPreservesCtiValue() {
        ObjectNode payload = request(true);
        this.action.preserveMetadata(indexReturning(storedDocument()), ID, payload, Space.STANDARD);
        assertFalse(payload.get(Constants.KEY_CTI_ENABLED).asBoolean());
    }

    /** A client cannot forge CTI's value. */
    public void testInjectedCtiEnabledIsIgnored() {
        ObjectNode payload = request(true);
        payload.put(Constants.KEY_CTI_ENABLED, true);

        this.action.preserveMetadata(indexReturning(storedDocument()), ID, payload, Space.STANDARD);

        assertFalse(payload.get(Constants.KEY_CTI_ENABLED).asBoolean());
    }

    /** On standard, enabled is derived — a value sent by the client must not win. */
    public void testEnabledSentByClientIsIgnoredOnStandard() {
        ObjectNode payload = request(true);
        payload.put(Constants.KEY_ENABLED, false);

        this.action.preserveMetadata(indexReturning(storedDocument()), ID, payload, Space.STANDARD);

        assertTrue(payload.get(Constants.KEY_ENABLED).asBoolean());
    }

    /** Stored draft document: fully editable, no CTI value. */
    private ObjectNode storedDraftDocument() {
        ObjectNode document = MAPPER.createObjectNode();
        document.put(Constants.KEY_ID, ID);
        document.put(Constants.KEY_ENABLED, false);
        document.put(Constants.KEY_MODE, "user-managed");
        document.put(Constants.KEY_CATEGORY, "other");
        document.set(Constants.KEY_METADATA, MAPPER.createObjectNode().put("title", "my-integration"));

        ObjectNode wrapper = MAPPER.createObjectNode();
        wrapper.set(Constants.KEY_DOCUMENT, document);
        wrapper.set(Constants.KEY_SPACE, MAPPER.createObjectNode().put("name", "draft"));
        return wrapper;
    }

    public void testDraftPutStoresUserChoiceAndDerivesEnabled() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put(Constants.KEY_ID, ID);
        payload.put(Constants.KEY_CATEGORY, "other");
        payload.put(Constants.KEY_USER_ENABLED, true);
        payload.set(Constants.KEY_METADATA, MAPPER.createObjectNode().put("title", "my-integration"));

        this.action.preserveMetadata(indexReturning(storedDraftDocument()), ID, payload, Space.DRAFT);

        assertTrue(payload.get(Constants.KEY_USER_ENABLED).asBoolean());
        assertTrue(payload.get(Constants.KEY_ENABLED).asBoolean());
    }

    /** A false choice is a real decision in draft too. */
    public void testDraftPutStoresFalseChoice() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put(Constants.KEY_ID, ID);
        payload.put(Constants.KEY_CATEGORY, "other");
        payload.put(Constants.KEY_USER_ENABLED, false);
        payload.set(Constants.KEY_METADATA, MAPPER.createObjectNode().put("title", "my-integration"));

        this.action.preserveMetadata(indexReturning(storedDraftDocument()), ID, payload, Space.DRAFT);

        assertFalse(payload.get(Constants.KEY_USER_ENABLED).asBoolean());
        assertFalse(payload.get(Constants.KEY_ENABLED).asBoolean());
    }

    /** On draft, an 'enabled' sent by the client must not win over the derivation. */
    public void testDraftEnabledSentByClientIsIgnored() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put(Constants.KEY_ID, ID);
        payload.put(Constants.KEY_CATEGORY, "other");
        payload.put(Constants.KEY_USER_ENABLED, true);
        payload.put(Constants.KEY_ENABLED, false);
        payload.set(Constants.KEY_METADATA, MAPPER.createObjectNode().put("title", "my-integration"));

        this.action.preserveMetadata(indexReturning(storedDraftDocument()), ID, payload, Space.DRAFT);

        assertTrue(payload.get(Constants.KEY_ENABLED).asBoolean());
    }

    /** A client cannot forge cti_enabled in draft either. */
    public void testDraftInjectedCtiEnabledIsStripped() {
        ObjectNode payload = MAPPER.createObjectNode();
        payload.put(Constants.KEY_ID, ID);
        payload.put(Constants.KEY_CATEGORY, "other");
        payload.put(Constants.KEY_USER_ENABLED, true);
        payload.put(Constants.KEY_CTI_ENABLED, true);
        payload.set(Constants.KEY_METADATA, MAPPER.createObjectNode().put("title", "my-integration"));

        this.action.preserveMetadata(indexReturning(storedDraftDocument()), ID, payload, Space.DRAFT);

        assertFalse(payload.has(Constants.KEY_CTI_ENABLED));
    }
}
