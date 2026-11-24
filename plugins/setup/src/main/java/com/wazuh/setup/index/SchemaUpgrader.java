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
package com.wazuh.setup.index;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.index.mapper.MapperException;

import java.io.IOException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.SchemaStatus;

/**
 * Brings the indices that {@link SchemaDriftDetector} reported as pending to the shipped schema
 * version, as far as it can be done without copying data.
 *
 * <p>An index that can be upgraded in place receives, in this order, the shipped mappings (without
 * their {@code _meta}), the shipped dynamic settings, and finally the shipped schema versions in
 * its {@code _meta}. The mappings go first because they are the only step OpenSearch can reject: a
 * field whose type changed is a conflict the versioning missed, and the index is then recorded as
 * {@link SchemaStatus#REBUILD_REQUIRED} with nothing else changed. The versions go last because
 * they are what the detection reads, so an upgrade interrupted before them is still pending on the
 * next boot and resumes after the step it recorded.
 *
 * <p>A data stream that must be rebuilt is rolled over instead: its new write index is created from
 * the stored template, and the previous backing indices keep their definition until retention
 * removes them. Any other index that must be rebuilt stays pending; the rebuilds are not automated
 * here.
 *
 * <p>A step that fails for another reason is logged and left pending, so the upgrade of the other
 * indices goes on and the failed one is retried on the next boot.
 */
public class SchemaUpgrader {
    private static final Logger log = LogManager.getLogger(SchemaUpgrader.class);

    private final Map<String, Index> indices;
    private final SetupStatusIndex statusIndex;

    /**
     * Constructor.
     *
     * @param indices every index the plugin manages.
     * @param statusIndex the index holding the records.
     */
    public SchemaUpgrader(List<Index> indices, SetupStatusIndex statusIndex) {
        this.indices = new HashMap<>();
        indices.forEach(index -> this.indices.put(index.getIndexName(), index));
        this.statusIndex = statusIndex;
    }

    /**
     * Upgrades every pending index and writes the resulting records.
     *
     * @param records the records the detection wrote, one per versioned index.
     * @return the records after the upgrade, in the same order. A record stays pending when its index
     *     could not be upgraded.
     */
    public List<IndexRecord> upgrade(List<IndexRecord> records) {
        List<IndexRecord> result = new ArrayList<>();
        for (IndexRecord record : records) {
            if (!record.isPending()) {
                result.add(record);
                continue;
            }
            Index index = this.indices.get(record.index());
            if (index == null) {
                log.error("No managed index named [{}]; its record is left as it is.", record.index());
                result.add(record);
                continue;
            }
            result.add(this.upgrade(index, record));
        }
        long pending = result.stream().filter(IndexRecord::isPending).count();
        if (pending == 0) {
            log.info("All {} managed indices are at the shipped schema version.", result.size());
        } else {
            log.warn("{} of {} managed indices still need a schema upgrade.", pending, result.size());
        }
        return result;
    }

    /**
     * Upgrades one index according to its status.
     *
     * @param index the index.
     * @param record its pending record.
     * @return the record after the upgrade.
     */
    private IndexRecord upgrade(Index index, IndexRecord record) {
        String name = record.index();
        try {
            return switch (record.status()) {
                case UPGRADE_IN_PLACE -> this.upgradeInPlace(index, record);
                case REBUILD_REQUIRED -> {
                    if (index instanceof StreamIndex stream) {
                        yield this.rollover(stream, record);
                    }
                    log.warn(
                            "Index [{}] must be rebuilt from the shipped template, which is not automated. It stays pending.",
                            name);
                    yield record;
                }
                default -> record;
            };
        } catch (Exception e) {
            log.error(
                    "Upgrade of [{}] failed and is retried on the next boot: {}", name, e.getMessage(), e);
            return this.statusIndex.getIndexRecord(name).orElse(record);
        }
    }

    /**
     * Applies the shipped mappings, settings and versions to the live index, resuming after the step
     * the record carries.
     *
     * @param index the index.
     * @param record its pending record.
     * @return the record after the upgrade: up to date, or rebuild required on a mapping conflict.
     * @throws IOException if the shipped template cannot be read.
     */
    private IndexRecord upgradeInPlace(Index index, IndexRecord record) throws IOException {
        String name = record.index();
        String step = record.step();
        log.info(
                "Upgrading [{}] in place from schema version {} to {}{}.",
                name,
                record.installed(),
                record.shipped(),
                step == null ? "" : ", resuming after step [" + step + "]");

        if (!Index.STEP_MAPPINGS_UPDATED.equals(step) && !Index.STEP_SETTINGS_UPDATED.equals(step)) {
            try {
                index.applyShippedMappings();
            } catch (IllegalArgumentException | MapperException e) {
                log.error(
                        "The shipped mappings of [{}] cannot be merged into the live index: {}. The index must be rebuilt.",
                        name,
                        e.getMessage());
                return this.write(
                        new IndexRecord(
                                name,
                                record.installed(),
                                record.shipped(),
                                record.compat(),
                                SchemaStatus.REBUILD_REQUIRED,
                                null,
                                Instant.now()));
            }
            step = Index.STEP_MAPPINGS_UPDATED;
            this.write(this.pending(record, step));
        }

        if (!Index.STEP_SETTINGS_UPDATED.equals(step)) {
            index.applyShippedSettings();
            step = Index.STEP_SETTINGS_UPDATED;
            this.write(this.pending(record, step));
        }

        index.stampShippedVersion();
        return this.write(
                IndexRecord.of(name, record.shipped(), record.shipped(), record.compat(), null));
    }

    /**
     * Rolls a data stream over and reads the version its new write index carries.
     *
     * @param stream the data stream.
     * @param record its pending record.
     * @return the record after the rollover.
     */
    private IndexRecord rollover(StreamIndex stream, IndexRecord record) {
        log.info(
                "Rolling over [{}]: its write index is at schema version {}, shipped {} (compatible from {}).",
                record.index(),
                record.installed(),
                record.shipped(),
                record.compat());
        stream.rollover();
        return this.write(
                IndexRecord.of(
                        record.index(),
                        stream.getInstalledSchemaVersion(),
                        record.shipped(),
                        record.compat(),
                        null));
    }

    private IndexRecord pending(IndexRecord record, String step) {
        return IndexRecord.of(
                record.index(), record.installed(), record.shipped(), record.compat(), step);
    }

    private IndexRecord write(IndexRecord record) {
        this.statusIndex.putIndexRecord(record);
        return record;
    }
}
