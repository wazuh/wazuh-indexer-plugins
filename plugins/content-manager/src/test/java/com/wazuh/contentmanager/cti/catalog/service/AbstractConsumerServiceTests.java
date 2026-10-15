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
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.common.settings.Settings;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.transport.client.Client;
import org.junit.After;
import org.junit.Before;

import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;
import com.wazuh.contentmanager.cti.console.model.Plan;
import com.wazuh.contentmanager.settings.PluginSettings;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for the per-consumer part of a pass in {@link AbstractConsumerService}: the offsets
 * its document shows while it synchronizes, and what it does with the outcome of the pass's swap.
 */
public class AbstractConsumerServiceTests extends OpenSearchTestCase {

    private static final String IOCS = "iocs";
    private static final String OPEN_IOCS = resource("open-iocs");
    private static final String PRO_IOCS = resource("pro-iocs");

    private List<String> events;
    private InMemoryConsumersIndex consumersIndex;
    private TestConsumer consumer;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        PluginSettings.resetForTesting();
        PluginSettings.getInstance(Settings.EMPTY);
        this.events = new ArrayList<>();
        this.consumersIndex = new InMemoryConsumersIndex();
        this.consumer =
                new TestConsumer(this.consumersIndex, IOCS, List.of("iocs"), false, this.events);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        PluginSettings.resetForTesting();
        super.tearDown();
    }

    /**
     * While an update runs, the document shows the remote offset it updates to next to the local
     * offset of the content already live. The remote offset is written by the same write that marks
     * the consumer running, before any change is applied, so no reader sees the running document with
     * the offsets of the previous pass. It completes with both equal.
     */
    public void testUpdateShowsTheGapUntilItCompletes() {
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 1000, 1000));
        this.consumersIndex.events = this.events;
        this.consumer.setRemote(remote("open-iocs", 1150, 900));

        boolean needsRetry = this.consumer.synchronize(SyncPass.withPlan(null));

        assertFalse(needsRetry);
        assertEquals(
                List.of(
                        "write iocs open-iocs running 1000/1150",
                        "update iocs 1000->1150",
                        "write iocs open-iocs running 1150/1150",
                        "post-sync iocs updated=true",
                        "write iocs open-iocs ready 1150/1150"),
                this.events);
    }

    /** A consumer already at the remote head writes no remote offset: there is no gap to show. */
    public void testUpToDateConsumerWritesNoRemoteOffset() {
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 1150, 1150));
        this.consumer.setRemote(remote("open-iocs", 1150, 900));

        this.consumer.synchronize(SyncPass.withPlan(null));

        assertEquals(List.of("running 1150/1150", "ready 1150/1150"), this.writtenStates());
        assertEquals(List.of("post-sync iocs updated=false"), this.events);
    }

    /**
     * A configured catalog URL other than the document's data source does not set the remote offset:
     * the offsets of another data source cannot be compared with the document's local offset.
     */
    public void testRemoteOffsetOfAnotherDataSourceIsNotRecorded() {
        this.consumer.customCatalogUri = resource("custom-iocs");
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 1000, 1000));
        this.consumer.setRemote(remote("custom-iocs", 5000, 4000));

        this.consumer.synchronize(SyncPass.withPlan(null));

        assertFalse(this.writtenStates().contains("running 1000/5000"));
    }

    /**
     * A consumer the pass's swap moved catches up from the loaded snapshot to the remote head and
     * completes on the new data source, with its post-synchronization work run as an update.
     */
    public void testSwappedConsumerCatchesUpAndCompletesOnTheNewSource() {
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 900120, 900120));
        this.consumer.setRemote(remote("pro-iocs", 803322, 777591));
        SyncPass pass = SyncPass.withPlan(plan());
        this.swap(pass);

        boolean needsRetry = this.consumer.synchronize(pass);

        assertFalse(needsRetry);
        assertEquals(SyncPass.SwapOutcome.SWAPPED, pass.swapOutcome(IOCS));
        assertEquals(
                List.of(
                        "load iocs",
                        "before switch iocs",
                        "update iocs 777591->803322",
                        "post-sync iocs updated=true"),
                this.events);
        LocalConsumer document = this.consumersIndex.documents.get(IOCS);
        assertEquals(PRO_IOCS, document.getResource());
        assertEquals("ready 803322/803322", state(document));
    }

    /**
     * A swapped consumer whose snapshot is already at the remote head has nothing to catch up, and
     * still runs its post-synchronization work as an update: its content was replaced.
     */
    public void testSwappedConsumerAtTheHeadStillCompletesAsAnUpdate() {
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 900120, 900120));
        this.consumer.setRemote(remote("pro-iocs", 803322, 803322));
        SyncPass pass = SyncPass.withPlan(plan());
        this.swap(pass);

        this.consumer.synchronize(pass);

        assertFalse(this.events.stream().anyMatch(e -> e.startsWith("update")));
        assertTrue(this.events.contains("post-sync iocs updated=true"));
        assertEquals("ready 803322/803322", state(this.consumersIndex.documents.get(IOCS)));
    }

    /**
     * A consumer whose data source changes but could not be swapped keeps its content as it is and
     * asks for a retry.
     */
    public void testPendingSourceChangeKeepsTheContent() {
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 900120, 900120));
        this.consumer.loadSucceeds = false;
        this.consumer.setRemote(remote("pro-iocs", 803322, 777591));
        SyncPass pass = SyncPass.withPlan(plan());
        this.swap(pass);

        boolean needsRetry = this.consumer.synchronize(pass);

        assertTrue(needsRetry);
        assertEquals(SyncPass.SwapOutcome.PENDING, pass.swapOutcome(IOCS));
        assertFalse(this.events.stream().anyMatch(e -> e.startsWith("update")));
        assertTrue(this.events.contains("post-sync iocs updated=false"));
        LocalConsumer document = this.consumersIndex.documents.get(IOCS);
        assertEquals(OPEN_IOCS, document.getResource());
        assertEquals("ready 900120/900120", state(document));
    }

    /** A consumer the swap holds is not touched at all, and asks for a retry. */
    public void testHeldConsumerIsLeftUntouched() {
        this.consumersIndex.put(document(PRO_IOCS, LocalConsumer.Status.RUNNING, 0, 803322));
        this.consumer.setRemote(remote("pro-iocs", 803322, 777591));
        SyncPass pass = SyncPass.withPlan(plan());
        pass.recordSwapOutcome(IOCS, SyncPass.SwapOutcome.HELD);

        boolean needsRetry = this.consumer.synchronize(pass);

        assertTrue(needsRetry);
        assertTrue(this.consumersIndex.writes.isEmpty());
        assertTrue(this.events.isEmpty());
    }

    /**
     * An offline pass rebuilds a consumer with content from the snapshot file placed in its snapshots
     * directory, whatever its offset, through a swap, and does not ask CTI for the remote consumer.
     * The document then records the highest offset of the file.
     */
    public void testOfflinePassRebuildsConsumerFromItsSnapshotFile() throws Exception {
        this.placeSnapshotFile();
        this.consumer.swapService = this.stubSwapService();
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 1000, 1000));
        this.consumer.setRemote(remote("open-iocs", 1500, 1400));

        boolean needsRetry = this.consumer.synchronize(SyncPass.offline());

        assertFalse(needsRetry);
        verify(this.consumer.consumerService, never()).getRemoteConsumer();
        assertEquals(
                List.of("load file iocs test.zip", "before switch iocs", "post-sync iocs updated=true"),
                this.events);
        assertEquals(
                List.of("running 1000/1000", "running 2000/2000", "ready 2000/2000"), this.writtenStates());
        assertTrue(this.consumer.swapPerformed());
    }

    /**
     * A snapshot file that cannot be loaded leaves the current content and its offsets as they are.
     */
    public void testOfflinePassKeepsContentWhenTheFileCannotBeLoaded() throws Exception {
        this.placeSnapshotFile();
        this.consumer.swapService = this.stubSwapService();
        this.consumer.fileOffset = -1;
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 1000, 1000));
        this.consumer.setRemote(remote("open-iocs", 1500, 1400));

        boolean needsRetry = this.consumer.synchronize(SyncPass.offline());

        assertFalse(needsRetry);
        assertEquals(List.of("load file iocs test.zip", "post-sync iocs updated=false"), this.events);
        assertEquals(List.of("running 1000/1000", "ready 1000/1000"), this.writtenStates());
        assertFalse(this.consumer.swapPerformed());
    }

    /**
     * An offline pass leaves a consumer without a snapshot file as it is, instead of reloading it
     * from the stable snapshot of an earlier load.
     */
    public void testOfflinePassLeavesConsumerWithoutSnapshotFile() throws Exception {
        this.consumer.snapshotsDir = createTempDir();
        Files.createFile(this.consumer.snapshotsDir.resolve("test.stable.zip"));
        SnapshotServiceImpl snapshotService = this.mockSnapshotService(1200);
        this.consumer.swapService = this.stubSwapService();
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 1000, 1000));
        this.consumer.setRemote(remote("open-iocs", 1500, 1400));

        boolean needsRetry = this.consumer.synchronize(SyncPass.offline());

        assertFalse(needsRetry);
        verify(snapshotService, never()).initialize(any(Path.class), any());
        assertEquals(List.of("post-sync iocs updated=false"), this.events);
    }

    /**
     * Without an offline pass, a snapshot file placed for a consumer that already has content is not
     * loaded while CTI cannot be reached: the offset says the content is there. This is why an
     * air-gapped deployment needs the offline update.
     */
    public void testRegularPassDoesNotLoadPlacedSnapshotFile() throws Exception {
        this.placeSnapshotFile();
        SnapshotServiceImpl snapshotService = this.mockSnapshotService(1200);
        this.consumer.swapService = this.stubSwapService();
        this.consumersIndex.put(document(OPEN_IOCS, LocalConsumer.Status.READY, 1000, 1000));
        this.consumer.setRemote(null);

        boolean needsRetry = this.consumer.synchronize(SyncPass.withPlan(null));

        assertTrue(needsRetry);
        verify(snapshotService, never()).initialize(any(Path.class), any());
        assertEquals(List.of("post-sync iocs updated=false"), this.events);
    }

    /** Only a snapshot file waiting to be loaded counts, not the stable one of an earlier load. */
    public void testHasLocalSnapshot() throws Exception {
        assertFalse(this.consumer.hasLocalSnapshot());
        this.consumer.snapshotsDir = createTempDir();
        Files.createFile(this.consumer.snapshotsDir.resolve("test.stable.zip"));
        assertFalse(this.consumer.hasLocalSnapshot());
        Files.createFile(this.consumer.snapshotsDir.resolve("test.zip"));
        assertTrue(this.consumer.hasLocalSnapshot());
    }

    /** Creates the consumer's snapshots directory with a snapshot file in it. */
    private Path placeSnapshotFile() throws Exception {
        this.consumer.snapshotsDir = createTempDir();
        return Files.createFile(this.consumer.snapshotsDir.resolve("test.zip"));
    }

    /** Gives the consumer a snapshot service whose local loads succeed up to {@code maxOffset}. */
    private SnapshotServiceImpl mockSnapshotService(long maxOffset) {
        SnapshotServiceImpl snapshotService = mock(SnapshotServiceImpl.class);
        when(snapshotService.initialize(any(Path.class), any())).thenReturn(true);
        when(snapshotService.getMaxOffsetSeen()).thenReturn(maxOffset);
        this.consumer.setSnapshotService(snapshotService);
        return snapshotService;
    }

    /** Runs the pass's swap for the consumer, without staging indices left from earlier passes. */
    private void swap(SyncPass pass) {
        this.stubSwapService().swapChangedSources(List.of(this.consumer), pass);
    }

    /** A swap service whose cluster operations do nothing. */
    private ShadowSwapService stubSwapService() {
        return new ShadowSwapService(mock(Client.class), this.consumersIndex) {
            @Override
            Map<String, ContentIndex> createStagingIndices(AbstractConsumerService consumer) {
                return Map.of();
            }

            @Override
            String livePhysicalName(String alias) {
                return alias + "-a";
            }

            @Override
            String shadowPhysicalName(String alias) {
                return alias + "-b";
            }

            @Override
            boolean shadowIndexExists(String alias) {
                return false;
            }

            @Override
            void refreshIndices(Collection<String> indices) {}

            @Override
            void switchAliases(Map<String, String> aliasToStaging, Map<String, String> aliasToLive) {}

            @Override
            void deleteIndices(Collection<String> indices) {}
        };
    }

    /** The status and offsets of every write of the consumer's document, in order. */
    private List<String> writtenStates() {
        return this.consumersIndex.writes.stream()
                .flatMap(w -> w.documents().stream())
                .map(AbstractConsumerServiceTests::state)
                .toList();
    }

    private static String state(LocalConsumer document) {
        return document.getStatus()
                + " "
                + document.getLocalOffset()
                + "/"
                + document.getRemoteOffset();
    }

    private static String resource(String name) {
        return "https://cti.example/api/v1/catalog/contexts/" + name + "/consumers/" + name;
    }

    private static LocalConsumer document(
            String resource, LocalConsumer.Status status, long localOffset, long remoteOffset) {
        String name = PluginSettings.getConsumerFromCatalogUri(resource);
        return new LocalConsumer(
                name, name, IOCS, resource, name.startsWith("open-"), status, localOffset, remoteOffset);
    }

    private static RemoteConsumer remote(String name, long head, long snapshotOffset) {
        RemoteConsumer remote = mock(RemoteConsumer.class);
        when(remote.getName()).thenReturn(name);
        when(remote.getContext()).thenReturn(name);
        when(remote.getOffset()).thenReturn(head);
        when(remote.getSnapshotOffset()).thenReturn(snapshotOffset);
        when(remote.getSnapshotLink()).thenReturn("https://cti.example/iocs.zip");
        when(remote.isPublic()).thenReturn(name.startsWith("open-"));
        return remote;
    }

    /** A plan that moves the IoC consumer to the pro feed. */
    private static Plan plan() {
        ObjectMapper mapper = new ObjectMapper();
        ObjectNode plan = mapper.createObjectNode().put("name", "Pro").put("is_public", false);
        plan.putArray("features").addObject().put("type", IOCS).put("resource", PRO_IOCS);
        return mapper.convertValue(plan, Plan.class);
    }
}
