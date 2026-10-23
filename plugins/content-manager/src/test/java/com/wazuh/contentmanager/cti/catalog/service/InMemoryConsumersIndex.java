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

import org.opensearch.action.get.GetResponse;
import org.opensearch.action.index.IndexResponse;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.transport.client.Client;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import com.wazuh.contentmanager.cti.catalog.index.ConsumersIndex;
import com.wazuh.contentmanager.cti.catalog.model.LocalConsumer;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * A {@link ConsumersIndex} that keeps the consumer documents in memory and records every write in
 * order, so tests can check what a reader of {@code .wazuh-cti-consumers} would have seen at each
 * step. Bulk writes can be made to fail by their position.
 */
class InMemoryConsumersIndex extends ConsumersIndex {

    /**
     * One write to the index.
     *
     * @param bulk Whether the documents were written together, in one bulk request.
     * @param documents The documents written.
     */
    record Write(boolean bulk, List<LocalConsumer> documents) {}

    /** The current document of each consumer type. */
    final Map<String, LocalConsumer> documents = new LinkedHashMap<>();

    /** Every write, in order. */
    final List<Write> writes = new ArrayList<>();

    /** The 1-based positions of the bulk writes that fail. */
    final Set<Integer> failingBulkWrites = new HashSet<>();

    /** Whether reads fail, as when the index is unavailable. */
    boolean readsFail;

    /** Whether single-document writes fail. */
    boolean writesFail;

    /** Every time recorded as the last check of the CTI catalog, in order. */
    final List<Instant> catalogChecks = new ArrayList<>();

    /** Whether recording the last check of the CTI catalog fails. */
    boolean catalogCheckFails;

    /** The consumer types whose document cannot be read while the others can. */
    final Set<String> unreadable = new HashSet<>();

    /** When set, every write is also appended here, to order writes against other events. */
    List<String> events;

    private int bulkWrites;

    InMemoryConsumersIndex() {
        super(mock(Client.class));
    }

    /** Stores a document as the state before the test, without recording a write. */
    void put(LocalConsumer document) {
        this.documents.put(document.getType(), document);
    }

    /** Returns the bulk writes, in order. */
    List<Write> bulkWrites() {
        return this.writes.stream().filter(Write::bulk).toList();
    }

    @Override
    public IndexResponse setConsumer(LocalConsumer consumer) {
        return this.setConsumer(consumer, false);
    }

    @Override
    public IndexResponse setConsumer(LocalConsumer consumer, boolean lightweight) {
        if (this.writesFail) {
            throw new IllegalStateException("write of [" + consumer.getType() + "] failed");
        }
        this.documents.put(consumer.getType(), consumer);
        this.writes.add(new Write(false, List.of(consumer)));
        if (this.events != null) {
            this.events.add("write " + describe(consumer));
        }
        return null;
    }

    @Override
    public void setConsumers(Collection<LocalConsumer> consumers) {
        this.bulkWrites++;
        if (this.failingBulkWrites.contains(this.bulkWrites)) {
            throw new IllegalStateException("bulk write " + this.bulkWrites + " failed");
        }
        consumers.forEach(c -> this.documents.put(c.getType(), c));
        this.writes.add(new Write(true, List.copyOf(consumers)));
        if (this.events != null) {
            this.events.add(
                    "bulk write " + consumers.stream().map(InMemoryConsumersIndex::describe).toList());
        }
    }

    @Override
    public IndexResponse setLastCheckedAt(Instant checkedAt) {
        if (this.catalogCheckFails) {
            throw new IllegalStateException("write of [" + CATALOG_ID + "] failed");
        }
        this.catalogChecks.add(checkedAt);
        return null;
    }

    /**
     * Describes a document by what a reader of the consumers panel sees: type, context, status and
     * local/remote offsets.
     */
    static String describe(LocalConsumer document) {
        return document.getType()
                + " "
                + document.getContext()
                + " "
                + document.getStatus()
                + " "
                + document.getLocalOffset()
                + "/"
                + document.getRemoteOffset();
    }

    @Override
    public GetResponse getConsumer(String type) {
        if (this.readsFail) {
            throw new IllegalStateException("Index not ready");
        }
        if (this.unreadable.contains(type)) {
            throw new IllegalStateException("No shard copy available for document [" + type + "]");
        }
        LocalConsumer document = this.documents.get(type);
        GetResponse response = mock(GetResponse.class);
        when(response.isExists()).thenReturn(document != null);
        if (document != null) {
            try {
                when(response.getSourceAsString())
                        .thenReturn(BytesReference.bytes(document.toXContent()).utf8ToString());
            } catch (IOException e) {
                throw new UncheckedIOException(e);
            }
        }
        return response;
    }
}
