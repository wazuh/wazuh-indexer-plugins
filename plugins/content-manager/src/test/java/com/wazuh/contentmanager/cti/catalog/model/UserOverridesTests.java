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
package com.wazuh.contentmanager.cti.catalog.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;

import java.util.List;
import java.util.Set;

import com.wazuh.contentmanager.utils.Constants;

/** Unit tests for {@link UserOverrides}. */
public class UserOverridesTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** A removal sticks, and enrichments CTI adds later still come through. */
    public void testEnrichmentDeltaRemovesAndLetsNewCtiValuesThrough() {
        UserOverrides.EnrichmentDelta delta =
                new UserOverrides.EnrichmentDelta(Set.of("geo"), Set.of());

        List<String> result = delta.applyTo(List.of("geo", "connection", "url_full"));
        assertEquals(List.of("connection", "url_full"), result);

        // CTI ships a new enrichment: the user who removed "geo" still receives it.
        List<String> withNewValue = delta.applyTo(List.of("geo", "connection", "url_full", "asn"));
        assertEquals(List.of("connection", "url_full", "asn"), withNewValue);
    }

    /** An addition survives even when CTI stops publishing it. */
    public void testEnrichmentDeltaKeepsUserAdditions() {
        UserOverrides.EnrichmentDelta delta =
                new UserOverrides.EnrichmentDelta(Set.of(), Set.of("custom_one"));

        assertEquals(List.of("connection", "custom_one"), delta.applyTo(List.of("connection")));
    }

    /** An empty delta leaves CTI's list untouched. */
    public void testEmptyEnrichmentDeltaIsIdentity() {
        UserOverrides.EnrichmentDelta delta = new UserOverrides.EnrichmentDelta(Set.of(), Set.of());

        assertEquals(List.of("geo", "connection"), delta.applyTo(List.of("geo", "connection")));
    }

    /**
     * What is written can be read back unchanged, and a setting the user never decided stays absent.
     */
    public void testRoundTripThroughRegistryNode() {
        ObjectNode root = MAPPER.createObjectNode();

        UserOverrides original =
                new UserOverrides(
                        new UserOverrides.PolicySettings(
                                Boolean.FALSE,
                                Boolean.TRUE,
                                null,
                                new UserOverrides.EnrichmentDelta(Set.of("geo"), Set.of())),
                        List.of(new UserOverrides.StoredFilter("filter-id", "{\"document\":{}}")),
                        List.of());

        original.writeInto(root, "standard");
        UserOverrides read = UserOverrides.forSpace(root, "standard");

        assertEquals(Boolean.FALSE, read.getPolicy().getEnabled());
        assertEquals(Boolean.TRUE, read.getPolicy().getIndexUnclassifiedEvents());
        assertNull(
                "a setting the user never decided must stay absent, not become false",
                read.getPolicy().getIndexDiscardedEvents());
        assertEquals(Set.of("geo"), read.getPolicy().getEnrichments().getRemoved());
        assertEquals(1, read.getFilters().size());
        assertEquals("filter-id", read.getFilters().get(0).getId());
        assertEquals("{\"document\":{}}", read.getFilters().get(0).getDocument());
    }

    /** An unknown space reads as empty rather than throwing. */
    public void testUnknownSpaceReadsAsEmpty() {
        UserOverrides read = UserOverrides.forSpace(MAPPER.createObjectNode(), "standard");

        assertNull(read.getPolicy());
        assertTrue(read.getFilters().isEmpty());
    }

    /** A missing registry reads as empty: a cluster that never stored an override is not an error. */
    public void testNullRegistryReadsAsEmpty() {
        UserOverrides read = UserOverrides.forSpace(null, "standard");

        assertNull(read.getPolicy());
        assertTrue(read.getFilters().isEmpty());
    }

    /**
     * Writing one space must not disturb another. The registry holds every space in a single
     * document, so a per-space write that clobbered its siblings would lose overrides silently.
     */
    public void testWritingOneSpaceLeavesAnotherIntact() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        new UserOverrides.PolicySettings(Boolean.FALSE, null, null, null),
                        List.of(new UserOverrides.StoredFilter("draft-filter", "{}")),
                        List.of())
                .writeInto(root, "draft");
        new UserOverrides(
                        new UserOverrides.PolicySettings(Boolean.TRUE, null, null, null), List.of(), List.of())
                .writeInto(root, "standard");

        assertEquals(Boolean.FALSE, UserOverrides.forSpace(root, "draft").getPolicy().getEnabled());
        assertEquals(1, UserOverrides.forSpace(root, "draft").getFilters().size());
        assertEquals(Boolean.TRUE, UserOverrides.forSpace(root, "standard").getPolicy().getEnabled());
    }

    /**
     * The written node must not contain a {@code space} field. The pre-snapshot wipe selects by
     * {@code space.name}, so a registry that carried one would delete itself on the next sync.
     */
    public void testWrittenNodeCarriesNoSpaceField() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        new UserOverrides.PolicySettings(Boolean.FALSE, null, null, null),
                        List.of(new UserOverrides.StoredFilter("f1", "{}")),
                        List.of(new UserOverrides.IntegrationOverride("i1", false)))
                .writeInto(root, "standard");

        assertFalse(root.toString().contains("\"" + Constants.KEY_SPACE + "\""));
    }

    /** An integration override round-trips with its id and its decision. */
    public void testIntegrationOverridesRoundTrip() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        null,
                        List.of(),
                        List.of(
                                new UserOverrides.IntegrationOverride("i1", false),
                                new UserOverrides.IntegrationOverride("i2", true)))
                .writeInto(root, "standard");

        UserOverrides read = UserOverrides.forSpace(root, "standard");

        assertEquals(2, read.getIntegrations().size());
        assertEquals("i1", read.getIntegrations().get(0).getId());
        assertEquals(Boolean.FALSE, read.getIntegrations().get(0).getEnabled());
        assertEquals(Boolean.TRUE, read.getIntegrations().get(1).getEnabled());
    }

    /** The three sections share one space entry, so writing one must not disturb the others. */
    public void testTheThreeSectionsCoexist() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        new UserOverrides.PolicySettings(Boolean.FALSE, null, null, null),
                        List.of(new UserOverrides.StoredFilter("f1", "{}")),
                        List.of(new UserOverrides.IntegrationOverride("i1", false)))
                .writeInto(root, "standard");

        UserOverrides read = UserOverrides.forSpace(root, "standard");

        assertEquals(Boolean.FALSE, read.getPolicy().getEnabled());
        assertEquals(1, read.getFilters().size());
        assertEquals(1, read.getIntegrations().size());
    }

    /** A registry written before integrations existed reads as an empty list, not null. */
    public void testIntegrationsAreEmptyWhenAbsent() {
        ObjectNode root = MAPPER.createObjectNode();
        new UserOverrides(null, List.of(new UserOverrides.StoredFilter("f1", "{}")), List.of())
                .writeInto(root, "standard");

        assertTrue(UserOverrides.forSpace(root, "standard").getIntegrations().isEmpty());
    }
}
