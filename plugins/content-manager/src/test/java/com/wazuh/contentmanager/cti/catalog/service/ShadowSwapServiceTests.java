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
package com.wazuh.contentmanager.cti.catalog.service;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.client.RegularUrlResolver;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ShadowSwapService}, over an in-memory alias topology and consumers index.
 *
 * <p>Three consumers start on the open feed, each on the {@code -a} slot of its aliases: a ruleset
 * with two aliases and user content, and two single-alias consumers. A pass whose plan provides the
 * pro feed for all three makes them all change data source.
 */
public class ShadowSwapServiceTests extends OpenSearchTestCase {

    private static final String RULESET = "ruleset";
    private static final String IOCS = "iocs";
    private static final String CVES = "cves";

    private List<String> events;
    private InMemoryConsumersIndex consumersIndex;
    private InMemorySwapService swapService;
    private TestConsumer ruleset;
    private TestConsumer iocs;
    private TestConsumer cves;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(Settings.EMPTY);
        this.events = new ArrayList<>();
        this.consumersIndex = new InMemoryConsumersIndex();
        this.consumersIndex.events = this.events;
        this.swapService = new InMemorySwapService(this.consumersIndex, this.events);

        this.ruleset = this.consumer(RULESET, List.of("rules", "decoders"), true, 1500, 4010, 4000);
        this.iocs = this.consumer(IOCS, List.of("iocs"), false, 900120, 803322, 777591);
        this.cves = this.consumer(CVES, List.of("cves"), false, 51200, 60300, 59000);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettings.resetForTesting();
        super.tearDown();
    }

    /**
     * Every consumer whose data source changes is staged first, its document changes together with
     * the others', and all their aliases switch in one request; the documents then record the
     * snapshot offsets, and only after that are the previous indices deleted.
     */
    public void testChangingConsumersSwitchTogetherInOneRequest() {
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertEquals(
                List.of(
                        "create staging ruleset",
                        "create staging iocs",
                        "create staging cves",
                        "bulk write [ruleset pro-ruleset running 0/4010, iocs pro-iocs running 0/803322,"
                                + " cves pro-cves running 0/60300]",
                        "load ruleset",
                        "load iocs",
                        "load cves",
                        "copy user content [rules-a, decoders-a]",
                        "before switch ruleset",
                        "before switch iocs",
                        "before switch cves",
                        "refresh [rules-b, decoders-b, iocs-b, cves-b]",
                        "switch [rules, decoders, iocs, cves]",
                        "bulk write [ruleset pro-ruleset running 4000/4010, iocs pro-iocs running"
                                + " 777591/803322, cves pro-cves running 59000/60300]",
                        "delete [rules-a, decoders-a]",
                        "delete [iocs-a]",
                        "delete [cves-a]"),
                this.events);
        assertEquals(1, this.swapService.switchRequests);
        assertEquals(
                Map.of("rules", "rules-b", "decoders", "decoders-b", "iocs", "iocs-b", "cves", "cves-b"),
                this.swapService.aliasTargets);
        assertEquals(Set.of("rules-b", "decoders-b", "iocs-b", "cves-b"), this.swapService.indices);
        for (String type : List.of(RULESET, IOCS, CVES)) {
            assertEquals(SyncPass.SwapOutcome.SWAPPED, pass.swapOutcome(type));
            LocalConsumer document = this.consumersIndex.documents.get(type);
            assertEquals(resource("pro-" + type), document.getResource());
            assertEquals("pro-" + type, document.getName());
            assertFalse(document.isPublic());
        }
        assertTrue(this.ruleset.swapPerformed());
    }

    /**
     * A snapshot that cannot be loaded keeps every consumer on its content: no alias switches, the
     * documents return to what they were, and only then are the staging indices deleted.
     */
    public void testFailedLoadKeepsEveryConsumerOnItsContent() {
        this.cves.loadSucceeds = false;
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertEquals(0, this.swapService.switchRequests);
        assertEquals(this.liveOnA(), this.swapService.aliasTargets);
        assertEquals(Set.of("rules-a", "decoders-a", "iocs-a", "cves-a"), this.swapService.indices);
        List<String> afterLoads =
                this.events.subList(this.events.indexOf("load cves") + 1, this.events.size());
        assertEquals(
                List.of(
                        "bulk write [ruleset open-ruleset ready 1500/1500, iocs open-iocs ready"
                                + " 900120/900120, cves open-cves ready 51200/51200]",
                        "delete [rules-b]",
                        "delete [decoders-b]",
                        "delete [iocs-b]",
                        "delete [cves-b]"),
                afterLoads);
        for (String type : List.of(RULESET, IOCS, CVES)) {
            assertEquals(SyncPass.SwapOutcome.PENDING, pass.swapOutcome(type));
            assertEquals(resource("open-" + type), this.consumersIndex.documents.get(type).getResource());
        }
        assertFalse(this.ruleset.swapPerformed());
    }

    /** A rejected alias request is undone like any other failure before the switch. */
    public void testRejectedSwitchKeepsEveryConsumerOnItsContent() {
        this.swapService.switchFails = true;
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertEquals(this.liveOnA(), this.swapService.aliasTargets);
        assertEquals(Set.of("rules-a", "decoders-a", "iocs-a", "cves-a"), this.swapService.indices);
        assertEquals(SyncPass.SwapOutcome.PENDING, pass.swapOutcome(IOCS));
        assertEquals("ready", this.consumersIndex.documents.get(IOCS).getStatus().toString());
    }

    /**
     * Staging indices that cannot be refreshed are not switched to, since searches would see only
     * part of them: every consumer keeps its content.
     */
    public void testFailedRefreshKeepsEveryConsumerOnItsContent() {
        this.swapService.refreshFails = true;
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertEquals(0, this.swapService.switchRequests);
        assertEquals(this.liveOnA(), this.swapService.aliasTargets);
        assertEquals(Set.of("rules-a", "decoders-a", "iocs-a", "cves-a"), this.swapService.indices);
        for (String type : List.of(RULESET, IOCS, CVES)) {
            assertEquals(SyncPass.SwapOutcome.PENDING, pass.swapOutcome(type));
            assertEquals(resource("open-" + type), this.consumersIndex.documents.get(type).getResource());
        }
    }

    /**
     * One consumer whose new data source offers no snapshot holds the change back for all of them:
     * nothing is created or written.
     */
    public void testUnavailableSnapshotPostponesEveryConsumer() {
        this.iocs.setRemote(remote("pro-iocs", 803322, 777591, ""));
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertTrue(this.events.isEmpty());
        assertTrue(this.consumersIndex.writes.isEmpty());
        for (String type : List.of(RULESET, IOCS, CVES)) {
            assertEquals(SyncPass.SwapOutcome.PENDING, pass.swapOutcome(type));
        }
    }

    /** Only the consumers whose data source changes move; the others are left as they are. */
    public void testOnlyChangingConsumersMove() {
        SyncPass pass = SyncPass.withPlan(plan(IOCS));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertTrue(this.events.contains("switch [iocs]"));
        assertEquals("iocs-b", this.swapService.aliasTargets.get("iocs"));
        assertEquals("rules-a", this.swapService.aliasTargets.get("rules"));
        assertEquals("cves-a", this.swapService.aliasTargets.get("cves"));
        assertEquals(SyncPass.SwapOutcome.SWAPPED, pass.swapOutcome(IOCS));
        assertEquals(SyncPass.SwapOutcome.UNCHANGED, pass.swapOutcome(RULESET));
        assertEquals(SyncPass.SwapOutcome.UNCHANGED, pass.swapOutcome(CVES));
    }

    /** A plan that could not be looked up never moves a consumer. */
    public void testUnknownPlanMovesNothing() {
        SyncPass pass = SyncPass.withUnknownPlan("CTI Console unavailable");

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertTrue(this.events.isEmpty());
        assertEquals(SyncPass.SwapOutcome.UNCHANGED, pass.swapOutcome(RULESET));
    }

    /**
     * A swap interrupted after the documents changed leaves them on the new data source, running, at
     * local offset 0, next to staging indices: the next pass redoes the swap.
     */
    public void testInterruptedSwapIsRedone() {
        this.interruptMidSwap();
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertEquals(1, this.swapService.switchRequests);
        assertEquals(
                Map.of("rules", "rules-b", "decoders", "decoders-b", "iocs", "iocs-b", "cves", "cves-b"),
                this.swapService.aliasTargets);
        for (String type : List.of(RULESET, IOCS, CVES)) {
            assertEquals(SyncPass.SwapOutcome.SWAPPED, pass.swapOutcome(type));
        }
        assertEquals(
                "iocs pro-iocs running 777591/803322",
                InMemoryConsumersIndex.describe(this.consumersIndex.documents.get(IOCS)));
    }

    /**
     * An interrupted swap that fails again keeps its staging indices: they mark it as interrupted,
     * and the documents do not describe the live content, so the consumers are held.
     */
    public void testFailedRedoOfInterruptedSwapKeepsItsStagingIndices() {
        this.interruptMidSwap();
        this.cves.loadSucceeds = false;
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertEquals(this.liveOnA(), this.swapService.aliasTargets);
        assertTrue(
                this.swapService.indices.containsAll(List.of("rules-b", "decoders-b", "iocs-b", "cves-b")));
        for (String type : List.of(RULESET, IOCS, CVES)) {
            assertEquals(SyncPass.SwapOutcome.HELD, pass.swapOutcome(type));
            assertTrue(ShadowSwapService.isMidSwap(this.consumersIndex.documents.get(type)));
        }
    }

    /** A document running at local offset 0 with nothing staged is not an interrupted swap. */
    public void testRunningDocumentWithoutStagingIndexIsNotAnInterruptedSwap() {
        this.consumersIndex.put(document(IOCS, "pro-iocs", LocalConsumer.Status.RUNNING, 0, 803322));
        SyncPass pass = SyncPass.withPlan(plan(IOCS));

        this.swapService.swapChangedSources(List.of(this.iocs), pass);

        assertTrue(this.events.isEmpty());
        assertEquals(SyncPass.SwapOutcome.UNCHANGED, pass.swapOutcome(IOCS));
    }

    /**
     * A staging index left next to a consumer whose document has content live, by a swap that could
     * not clean up, is deleted.
     */
    public void testLeftoverStagingIndexIsDeleted() {
        this.swapService.indices.add("iocs-b");
        SyncPass pass = SyncPass.withPlan(null);

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertEquals(List.of("delete [iocs-b]"), this.events);
        assertEquals(SyncPass.SwapOutcome.UNCHANGED, pass.swapOutcome(IOCS));
    }

    /**
     * Documents that cannot be restored after a failure still name the new data sources: the staging
     * indices are kept so the next pass redoes the swap, and the consumers are held.
     */
    public void testUnrestoredDocumentsKeepTheStagingIndices() {
        this.cves.loadSucceeds = false;
        this.consumersIndex.failingBulkWrites.add(2);
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertFalse(this.events.stream().anyMatch(e -> e.startsWith("delete")));
        assertTrue(
                this.swapService.indices.containsAll(List.of("rules-b", "decoders-b", "iocs-b", "cves-b")));
        assertEquals(SyncPass.SwapOutcome.HELD, pass.swapOutcome(IOCS));
    }

    /**
     * Offsets that cannot be recorded after the switch leave the documents at local offset 0: the
     * previous indices are kept, so the next pass redoes the swap, and the consumers are held.
     */
    public void testUnrecordedSwitchHoldsTheConsumers() {
        this.consumersIndex.failingBulkWrites.add(2);
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertEquals("iocs-b", this.swapService.aliasTargets.get("iocs"));
        assertTrue(
                this.swapService.indices.containsAll(List.of("rules-a", "decoders-a", "iocs-a", "cves-a")));
        for (String type : List.of(RULESET, IOCS, CVES)) {
            assertEquals(SyncPass.SwapOutcome.HELD, pass.swapOutcome(type));
        }
    }

    /** A consumer whose document cannot be read is held: whether it is mid-swap is unknown. */
    public void testUnreadableDocumentHoldsTheConsumer() {
        this.consumersIndex.readsFail = true;
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertTrue(this.events.isEmpty());
        assertEquals(SyncPass.SwapOutcome.HELD, pass.swapOutcome(RULESET));
    }

    /**
     * A consumer whose document cannot be read may be changing data source too, so the consumers that
     * do change wait for it: none of them moves, and their documents and aliases stay as they are.
     */
    public void testUndecidedConsumerPostponesEveryConsumer() {
        this.consumersIndex.unreadable.add(RULESET);
        SyncPass pass = SyncPass.withPlan(plan(RULESET, IOCS, CVES));

        this.swapService.swapChangedSources(this.consumers(), pass);

        assertTrue(this.events.isEmpty());
        assertEquals(0, this.swapService.switchRequests);
        assertEquals(this.liveOnA(), this.swapService.aliasTargets);
        assertEquals(SyncPass.SwapOutcome.HELD, pass.swapOutcome(RULESET));
        for (String type : List.of(IOCS, CVES)) {
            assertEquals(SyncPass.SwapOutcome.PENDING, pass.swapOutcome(type));
            assertEquals(resource("open-" + type), this.consumersIndex.documents.get(type).getResource());
        }
    }

    /**
     * A rebuild from the data source a consumer is already on leaves its document alone until the
     * switch, then records the snapshot offset.
     */
    public void testRebuildRecordsTheSnapshotOffsetOnlyAfterTheSwitch() {
        boolean rebuilt =
                this.swapService.rebuild(
                        this.cves,
                        resource("open-" + CVES),
                        remote("open-" + CVES, 51300, 51250, "https://cti.example/cves.zip"),
                        new RegularUrlResolver());

        assertTrue(rebuilt);
        assertEquals(
                List.of(
                        "create staging cves",
                        "load cves",
                        "before switch cves",
                        "refresh [cves-b]",
                        "switch [cves]",
                        "bulk write [cves open-cves running 51250/51300]",
                        "delete [cves-a]"),
                this.events);
    }

    /**
     * A rebuild from a snapshot file stays on the consumer's data source, carries its user content
     * over, and records the highest offset of the file as both offsets once the aliases switched.
     */
    public void testRebuildFromFileCarriesUserContentAndRecordsTheFileOffset() {
        this.ruleset.fileOffset = 1600;

        boolean rebuilt =
                this.swapService.rebuildFromFile(
                        this.ruleset,
                        this.consumersIndex.documents.get(RULESET),
                        Path.of("/snapshots/ruleset.zip"));

        assertTrue(rebuilt);
        assertEquals(
                List.of(
                        "create staging ruleset",
                        "load file ruleset ruleset.zip",
                        "copy user content [rules-a, decoders-a]",
                        "before switch ruleset",
                        "refresh [rules-b, decoders-b]",
                        "switch [rules, decoders]",
                        "bulk write [ruleset open-ruleset running 1600/1600]",
                        "delete [rules-a, decoders-a]"),
                this.events);
        assertTrue(this.ruleset.swapPerformed());
    }

    /** A snapshot file that cannot be loaded keeps the live content and drops the staging indices. */
    public void testFailedRebuildFromFileKeepsTheContent() {
        this.cves.fileOffset = -1;

        boolean rebuilt =
                this.swapService.rebuildFromFile(
                        this.cves, this.consumersIndex.documents.get(CVES), Path.of("/snapshots/cves.zip"));

        assertFalse(rebuilt);
        assertEquals(
                List.of("create staging cves", "load file cves cves.zip", "delete [cves-b]"), this.events);
        assertEquals("cves-a", this.swapService.aliasTargets.get("cves"));
        assertEquals(51200, this.consumersIndex.documents.get(CVES).getLocalOffset());
    }

    /** Leaves the three consumers as a swap interrupted before its switch would. */
    private void interruptMidSwap() {
        this.consumersIndex.put(
                document(RULESET, "pro-ruleset", LocalConsumer.Status.RUNNING, 0, 4010));
        this.consumersIndex.put(document(IOCS, "pro-iocs", LocalConsumer.Status.RUNNING, 0, 803322));
        this.consumersIndex.put(document(CVES, "pro-cves", LocalConsumer.Status.RUNNING, 0, 60300));
        this.swapService.indices.addAll(List.of("rules-b", "decoders-b", "iocs-b", "cves-b"));
    }

    private List<TestConsumer> consumers() {
        return List.of(this.ruleset, this.iocs, this.cves);
    }

    private Map<String, String> liveOnA() {
        return Map.of("rules", "rules-a", "decoders", "decoders-a", "iocs", "iocs-a", "cves", "cves-a");
    }

    /**
     * Creates a consumer synced to the open feed at the given offset, whose pro feed is at the given
     * head and snapshot offsets.
     */
    private TestConsumer consumer(
            String type,
            List<String> aliases,
            boolean userContent,
            long openOffset,
            long proHead,
            long proSnapshotOffset) {
        TestConsumer consumer =
                new TestConsumer(this.consumersIndex, type, aliases, userContent, this.events);
        consumer.setRemote(
                remote("pro-" + type, proHead, proSnapshotOffset, "https://cti.example/" + type + ".zip"));
        this.consumersIndex.put(
                document(type, "open-" + type, LocalConsumer.Status.READY, openOffset, openOffset));
        aliases.forEach(this.swapService::addLive);
        return consumer;
    }

    private static String resource(String name) {
        return "https://cti.example/api/v1/catalog/contexts/" + name + "/consumers/" + name;
    }

    private static LocalConsumer document(
            String type, String name, LocalConsumer.Status status, long localOffset, long remoteOffset) {
        return new LocalConsumer(
                name,
                name,
                type,
                resource(name),
                name.startsWith("open-"),
                status,
                localOffset,
                remoteOffset);
    }

    private static RemoteConsumer remote(
            String name, long head, long snapshotOffset, String snapshotLink) {
        RemoteConsumer remote = mock(RemoteConsumer.class);
        when(remote.getName()).thenReturn(name);
        when(remote.getContext()).thenReturn(name);
        when(remote.getOffset()).thenReturn(head);
        when(remote.getSnapshotOffset()).thenReturn(snapshotOffset);
        when(remote.getSnapshotLink()).thenReturn(snapshotLink);
        when(remote.isPublic()).thenReturn(name.startsWith("open-"));
        return remote;
    }

    /** A plan whose features move the given consumer types to the pro feed. */
    private static Plan plan(String... types) {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode plan = mapper.createObjectNode().put("name", "Pro").put("is_public", false);
        ArrayNode features = plan.putArray("features");
        for (String type : types) {
            features.addObject().put("type", type).put("resource", resource("pro-" + type));
        }
        return mapper.convertValue(plan, Plan.class);
    }

    /**
     * A ShadowSwapService over an in-memory topology: aliases point at {@code -a} or {@code -b}
     * physical indices, and each cluster operation is appended to the event log.
     */
    private static class InMemorySwapService extends ShadowSwapService {
        final Map<String, String> aliasTargets = new LinkedHashMap<>();
        final Set<String> indices = new LinkedHashSet<>();
        private final List<String> events;
        boolean refreshFails;
        boolean switchFails;
        int switchRequests;

        InMemorySwapService(InMemoryConsumersIndex consumersIndex, List<String> events) {
            super(mock(Client.class), consumersIndex);
            this.events = events;
        }

        void addLive(String alias) {
            this.aliasTargets.put(alias, alias + "-a");
            this.indices.add(alias + "-a");
        }

        @Override
        Map<String, ContentIndex> createStagingIndices(AbstractConsumerService consumer) {
            Map<String, ContentIndex> staging = new LinkedHashMap<>();
            for (Map.Entry<String, String> entry : consumer.getMappings().entrySet()) {
                String alias = consumer.getIndexName(entry.getKey());
                String physical = this.shadowPhysicalName(alias);
                this.indices.add(physical);
                staging.put(
                        entry.getKey(),
                        new ContentIndex(mock(Client.class), alias, physical, entry.getValue()));
            }
            this.events.add("create staging " + consumer.getConsumerType());
            return staging;
        }

        @Override
        String livePhysicalName(String alias) {
            return this.aliasTargets.get(alias);
        }

        @Override
        String shadowPhysicalName(String alias) {
            return this.aliasTargets.get(alias).endsWith("-a") ? alias + "-b" : alias + "-a";
        }

        @Override
        boolean shadowIndexExists(String alias) {
            return this.indices.contains(this.shadowPhysicalName(alias));
        }

        @Override
        void copyUserContent(Map<String, String> liveToStaging) {
            this.events.add("copy user content " + liveToStaging.keySet());
        }

        @Override
        void refreshIndices(Collection<String> names) {
            this.events.add("refresh " + names);
            if (this.refreshFails) {
                throw new IllegalStateException("shards could not be refreshed");
            }
        }

        @Override
        void switchAliases(Map<String, String> aliasToStaging, Map<String, String> aliasToLive) {
            this.switchRequests++;
            this.events.add("switch " + aliasToStaging.keySet());
            if (this.switchFails) {
                throw new IllegalStateException("alias request rejected");
            }
            this.aliasTargets.putAll(aliasToStaging);
        }

        @Override
        void deleteIndices(Collection<String> names) {
            this.events.add("delete " + names);
            this.indices.removeAll(names);
        }
    }
}
