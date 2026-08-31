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

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;

import java.util.List;

import com.wazuh.contentmanager.utils.Constants;

/** Unit tests for {@link UserOverrides}. */
public class UserOverridesTests extends OpenSearchTestCase {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    /** The stored enrichment list round-trips verbatim. */
    public void testEnrichmentListRoundTrips() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        new UserOverrides.PolicySettings(null, null, null, List.of("connection", "url_full")),
                        List.of(),
                        List.of())
                .writeInto(root, "standard");

        assertEquals(
                List.of("connection", "url_full"),
                UserOverrides.forSpace(root, "standard").getPolicy().getEnrichments());
    }

    /**
     * A user who never saved has no list, which is not the same as having saved an empty one. Absence
     * means CTI decides; an empty list means the user unchecked everything.
     */
    public void testAbsentEnrichmentListStaysNull() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        new UserOverrides.PolicySettings(Boolean.TRUE, null, null, null), List.of(), List.of())
                .writeInto(root, "standard");

        assertNull(UserOverrides.forSpace(root, "standard").getPolicy().getEnrichments());
    }

    /** And an empty list survives as an empty list. */
    public void testEmptyEnrichmentListIsPreserved() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        new UserOverrides.PolicySettings(null, null, null, List.of()), List.of(), List.of())
                .writeInto(root, "standard");

        assertEquals(List.of(), UserOverrides.forSpace(root, "standard").getPolicy().getEnrichments());
    }

    /**
     * What is written can be read back unchanged, and a setting the user never decided stays absent.
     */
    public void testRoundTripThroughRegistryNode() {
        ObjectNode root = MAPPER.createObjectNode();

        UserOverrides original =
                new UserOverrides(
                        new UserOverrides.PolicySettings(
                                Boolean.FALSE, Boolean.TRUE, null, List.of("connection")),
                        List.of(new UserOverrides.StoredFilter("filter-id", "{\"document\":{}}")),
                        List.of());

        original.writeInto(root, "standard");
        UserOverrides read = UserOverrides.forSpace(root, "standard");

        assertEquals(Boolean.FALSE, read.getPolicy().getEnabled());
        assertEquals(Boolean.TRUE, read.getPolicy().getIndexUnclassifiedEvents());
        assertNull(
                "a setting the user never decided must stay absent, not become false",
                read.getPolicy().getIndexDiscardedEvents());
        assertEquals(List.of("connection"), read.getPolicy().getEnrichments());
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
                        List.of(new UserOverrides.IntegrationOverride("i1", false, null)))
                .writeInto(root, "standard");

        assertFalse(root.toString().contains("\"" + Constants.KEY_SPACE + "\""));
    }

    /**
     * Integrations are written as an object keyed by id, not as an array.
     *
     * <p>That is what lets Security Analytics record a detector decision with a single partial
     * update: a {@code doc} merge combines objects recursively but replaces arrays wholesale, so an
     * array would force it to read, modify and write the whole document under optimistic concurrency.
     */
    public void testIntegrationsAreWrittenAsAMapKeyedById() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        null,
                        List.of(),
                        List.of(
                                new UserOverrides.IntegrationOverride("i1", false, null),
                                new UserOverrides.IntegrationOverride("i2", true, null)))
                .writeInto(root, "standard");

        JsonNode written = root.path("standard").path(Constants.KEY_INTEGRATION_OVERRIDES);
        assertTrue("must be an object, not an array", written.isObject());
        assertFalse(written.path("i1").path(Constants.KEY_ENABLED).asBoolean());
        assertTrue(written.path("i2").path(Constants.KEY_ENABLED).asBoolean());
    }

    /**
     * The two decisions are independent, and either may be absent.
     *
     * <p>Stopping a detector must not fabricate an opinion about its integration: recording {@code
     * false} there would disable an integration nobody asked to disable, and the override always wins
     * over CTI.
     */
    public void testDetectorDecisionIsIndependentOfTheIntegrationOne() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        null,
                        List.of(),
                        List.of(
                                new UserOverrides.IntegrationOverride("detector-only", null, Boolean.FALSE),
                                new UserOverrides.IntegrationOverride("integration-only", Boolean.FALSE, null)))
                .writeInto(root, "standard");

        UserOverrides read = UserOverrides.forSpace(root, "standard");

        assertEquals("detector-only", read.getIntegrations().get(0).getId());
        assertNull(
                "stopping a detector says nothing about the integration",
                read.getIntegrations().get(0).getEnabled());
        assertEquals(Boolean.FALSE, read.getIntegrations().get(0).getDetectorEnabled());

        assertEquals("integration-only", read.getIntegrations().get(1).getId());
        assertEquals(Boolean.FALSE, read.getIntegrations().get(1).getEnabled());
        assertNull(
                "disabling an integration says nothing about the detector on its own",
                read.getIntegrations().get(1).getDetectorEnabled());
    }

    /** And read back with the key as the id, so the id is not duplicated inside the entry. */
    public void testIntegrationsAreReadFromTheMapKey() {
        ObjectNode root = MAPPER.createObjectNode();
        new UserOverrides(
                        null, List.of(), List.of(new UserOverrides.IntegrationOverride("i1", false, null)))
                .writeInto(root, "standard");

        UserOverrides read = UserOverrides.forSpace(root, "standard");

        assertEquals(1, read.getIntegrations().size());
        assertEquals("i1", read.getIntegrations().get(0).getId());
        assertEquals(Boolean.FALSE, read.getIntegrations().get(0).getEnabled());
    }

    /** An integration override round-trips with its id and its decision. */
    public void testIntegrationOverridesRoundTrip() {
        ObjectNode root = MAPPER.createObjectNode();

        new UserOverrides(
                        null,
                        List.of(),
                        List.of(
                                new UserOverrides.IntegrationOverride("i1", false, null),
                                new UserOverrides.IntegrationOverride("i2", true, null)))
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
                        List.of(new UserOverrides.IntegrationOverride("i1", false, null)))
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
