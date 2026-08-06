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

import org.opensearch.action.bulk.BulkRequest;
import org.opensearch.action.index.IndexRequest;
import org.opensearch.action.support.ActionFilterChain;
import org.opensearch.action.support.ActionRequestMetadata;
import org.opensearch.action.update.UpdateRequest;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.action.ActionListener;
import org.opensearch.test.OpenSearchTestCase;

import java.util.Map;

import static org.mockito.Mockito.*;

/** Unit tests for the {@link AIAssistantSettingsVisibilityFilter} class. */
public class AIAssistantSettingsVisibilityFilterTests extends OpenSearchTestCase {

    private AIAssistantSettingsVisibilityFilter filter;
    private ActionFilterChain chain;
    private ActionListener listener;

    @Override
    @SuppressWarnings("unchecked")
    public void setUp() throws Exception {
        super.setUp();
        this.filter = new AIAssistantSettingsVisibilityFilter();
        this.chain = mock(ActionFilterChain.class);
        this.listener = mock(ActionListener.class);
    }

    @SuppressWarnings("unchecked")
    private void apply(org.opensearch.action.ActionRequest request) {
        this.filter.apply(
                null, "action", request, ActionRequestMetadata.empty(), this.listener, this.chain);
    }

    private IndexRequest documentFor(String index) {
        return new IndexRequest(index)
                .source(Map.of("providers", Map.of("name", "test-ai")), XContentType.JSON);
    }

    /** A document written to the settings index carries the administrator backend roles. */
    public void testIndexRequestIsStamped() {
        IndexRequest request = documentFor(AIAssistantSettingsIndex.INDEX_NAME);

        apply(request);

        assertEquals(
                AIAssistantSettingsIndex.VISIBLE_TO,
                request.sourceAsMap().get(AIAssistantSettingsIndex.VISIBILITY_FIELD));
        verify(this.chain).proceed(null, "action", request, this.listener);
    }

    /** A value sent by the client is overwritten, never trusted. */
    public void testClientSuppliedValueIsOverwritten() {
        IndexRequest request =
                new IndexRequest(AIAssistantSettingsIndex.INDEX_NAME)
                        .source(
                                Map.of(AIAssistantSettingsIndex.VISIBILITY_FIELD, java.util.List.of("attacker")),
                                XContentType.JSON);

        apply(request);

        assertEquals(
                AIAssistantSettingsIndex.VISIBLE_TO,
                request.sourceAsMap().get(AIAssistantSettingsIndex.VISIBILITY_FIELD));
    }

    /** Documents written to any other index are left untouched. */
    public void testOtherIndicesAreNotStamped() {
        IndexRequest request = documentFor("wazuh-states-inventory-packages");

        apply(request);

        assertFalse(request.sourceAsMap().containsKey(AIAssistantSettingsIndex.VISIBILITY_FIELD));
    }

    /** Rollovers and aliases keep the prefix, so the whole pattern is covered. */
    public void testIndicesMatchingThePrefixAreStamped() {
        IndexRequest request = documentFor(AIAssistantSettingsIndex.INDEX_NAME + "-000002");

        apply(request);

        assertEquals(
                AIAssistantSettingsIndex.VISIBLE_TO,
                request.sourceAsMap().get(AIAssistantSettingsIndex.VISIBILITY_FIELD));
    }

    /** Bulk requests are stamped item by item, leaving the unrelated ones alone. */
    public void testBulkRequestIsStampedPerItem() {
        IndexRequest settingsDocument = documentFor(AIAssistantSettingsIndex.INDEX_NAME);
        IndexRequest otherDocument = documentFor("wazuh-states-inventory-packages");
        BulkRequest request = new BulkRequest().add(settingsDocument).add(otherDocument);

        apply(request);

        assertEquals(
                AIAssistantSettingsIndex.VISIBLE_TO,
                settingsDocument.sourceAsMap().get(AIAssistantSettingsIndex.VISIBILITY_FIELD));
        assertFalse(otherDocument.sourceAsMap().containsKey(AIAssistantSettingsIndex.VISIBILITY_FIELD));
    }

    /** An upsert creates a document from scratch, so it needs the field too. */
    public void testUpdateRequestUpsertIsStamped() {
        IndexRequest upsert = documentFor(AIAssistantSettingsIndex.INDEX_NAME);
        UpdateRequest request =
                new UpdateRequest(AIAssistantSettingsIndex.INDEX_NAME, "1")
                        .doc(Map.of("providers", Map.of("name", "test-ai")))
                        .upsert(upsert);

        apply(request);

        assertEquals(
                AIAssistantSettingsIndex.VISIBLE_TO,
                request.upsertRequest().sourceAsMap().get(AIAssistantSettingsIndex.VISIBILITY_FIELD));
        assertEquals(
                AIAssistantSettingsIndex.VISIBLE_TO,
                request.doc().sourceAsMap().get(AIAssistantSettingsIndex.VISIBILITY_FIELD));
    }

    /** A {@code doc_as_upsert} request carries no separate upsert document, only the partial one. */
    public void testDocAsUpsertIsStamped() {
        UpdateRequest request =
                new UpdateRequest(AIAssistantSettingsIndex.INDEX_NAME, "1")
                        .doc(Map.of("providers", Map.of("name", "test-ai")))
                        .docAsUpsert(true);
        apply(request);

        assertEquals(
                AIAssistantSettingsIndex.VISIBLE_TO,
                request.doc().sourceAsMap().get(AIAssistantSettingsIndex.VISIBILITY_FIELD));
    }

    /** An update aimed at any other index is left untouched. */
    public void testUpdateRequestOnOtherIndexIsNotStamped() {
        UpdateRequest request =
                new UpdateRequest("wazuh-states-inventory-packages", "1")
                        .doc(Map.of("name", "openssl"))
                        .docAsUpsert(true);

        apply(request);

        assertFalse(
                request.doc().sourceAsMap().containsKey(AIAssistantSettingsIndex.VISIBILITY_FIELD));
    }
}
