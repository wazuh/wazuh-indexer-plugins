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

import org.opensearch.env.Environment;
import org.opensearch.transport.client.Client;

import java.nio.file.Path;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.client.ResourceUrlResolver;
import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;
import com.wazuh.contentmanager.cti.catalog.model.RemoteConsumer;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A consumer over test doubles. Its content aliases are the keys of its mappings, the remote
 * consumer is the one given to {@link #setRemote}, snapshot loads and incremental updates are
 * scripted, and each step is appended to a shared event log.
 */
class TestConsumer extends AbstractConsumerService {
    private final String type;
    private final List<String> aliases;
    private final boolean userContent;
    private final List<String> events;

    /** The catalog URL configured for this consumer, empty for none. */
    String customCatalogUri = "";

    /** The snapshots directory of this consumer's node, {@code null} for none. */
    Path snapshotsDir;

    /** The consumer service {@link #setRemote(RemoteConsumer)} installed, to verify its calls. */
    ConsumerService consumerService;

    /** The swap service rebuilds from a snapshot file go through, {@code null} for the real one. */
    ShadowSwapService swapService;

    /** The highest offset of the snapshot file a staging load reads, {@code -1} for a failed load. */
    long fileOffset = 2000;

    /** Whether snapshot loads into staging indices succeed. */
    boolean loadSucceeds = true;

    /**
     * Constructs a TestConsumer.
     *
     * @param consumersIndex The consumers index holding its document.
     * @param type The consumer type.
     * @param aliases The public aliases of its content indices.
     * @param userContent Whether its indices hold user content to carry across a swap.
     * @param events The shared event log.
     */
    TestConsumer(
            InMemoryConsumersIndex consumersIndex,
            String type,
            List<String> aliases,
            boolean userContent,
            List<String> events) {
        super(mock(Client.class), consumersIndex, mock(Environment.class));
        this.type = type;
        this.aliases = aliases;
        this.userContent = userContent;
        this.events = events;
    }

    /**
     * Makes the given remote consumer the one this consumer fetches, whatever its data source.
     *
     * @param remoteConsumer The remote consumer, or {@code null} for an unreachable feed.
     */
    void setRemote(RemoteConsumer remoteConsumer) {
        ConsumerService consumerService = mock(ConsumerService.class);
        when(consumerService.getRemoteConsumer()).thenReturn(remoteConsumer);
        when(consumerService.getLocalConsumer()).thenAnswer(invocation -> this.readConsumerDocument());
        this.setConsumerService(consumerService);
        this.consumerService = consumerService;
    }

    @Override
    Path resolveSnapshotsDir() {
        return this.snapshotsDir;
    }

    /** Returns whether a swap replaced this consumer's content. */
    boolean swapPerformed() {
        return this.shadowSwapPerformed;
    }

    @Override
    protected String getConsumerType() {
        return this.type;
    }

    @Override
    protected String getCustomCatalogUri() {
        return this.customCatalogUri;
    }

    @Override
    protected boolean hasUserContent() {
        return this.userContent;
    }

    @Override
    protected Map<String, String> getMappings() {
        Map<String, String> mappings = new LinkedHashMap<>();
        this.aliases.forEach(alias -> mappings.put(alias, "/mappings/consumers-mapping.json"));
        return mappings;
    }

    @Override
    public String getIndexName(String type) {
        return type;
    }

    @Override
    protected String getSnapshotFilename() {
        return "test.zip";
    }

    @Override
    public List<String> missingTargetIndices() {
        return List.of();
    }

    @Override
    protected void onBeforeAliasSwap() {
        this.events.add("before switch " + this.type);
    }

    @Override
    public void onSyncComplete(boolean isUpdated) {
        this.events.add("post-sync " + this.type + " updated=" + isUpdated);
    }

    @Override
    boolean loadStagedSnapshot(
            Map<String, ContentIndex> stagingIndices,
            RemoteConsumer remoteConsumer,
            ResourceUrlResolver urlResolver) {
        this.events.add("load " + this.type);
        return this.loadSucceeds;
    }

    @Override
    long loadStagedSnapshotFile(Map<String, ContentIndex> stagingIndices, Path snapshot) {
        this.events.add("load file " + this.type + " " + snapshot.getFileName());
        return this.fileOffset;
    }

    @Override
    boolean rebuildFromSnapshotFile(LocalConsumer current, Path snapshot) {
        return this.swapService != null
                ? this.swapService.rebuildFromFile(this, current, snapshot)
                : super.rebuildFromSnapshotFile(current, snapshot);
    }

    /** Records the update and, like {@link UpdateServiceImpl}, checkpoints the offset reached. */
    @Override
    boolean performIncrementalUpdate(
            String context,
            String consumer,
            String consumerType,
            String catalogUri,
            ResourceUrlResolver urlResolver,
            Map<String, ContentIndex> indicesMap,
            long fromOffset,
            long toOffset) {
        this.events.add("update " + this.type + " " + fromOffset + "->" + toOffset);
        try {
            LocalConsumer current = this.readConsumerDocument();
            this.consumersIndex.setConsumer(
                    new LocalConsumer(
                            current.getContext(),
                            current.getName(),
                            current.getType(),
                            current.getResource(),
                            current.isPublic(),
                            LocalConsumer.Status.RUNNING,
                            toOffset,
                            toOffset,
                            current.getPendingSyncPhases()),
                    true);
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return true;
    }
}
