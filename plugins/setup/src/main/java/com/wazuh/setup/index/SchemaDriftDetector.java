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

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import com.wazuh.setup.model.IndexRecord;
import com.wazuh.setup.model.IndexTemplate;

/**
 * Compares the schema version every managed index carries against the versions its shipped template
 * declares, and records the result in the {@code .wazuh-setup-status} index.
 *
 * <p>The Setup plugin runs the detection at every initialization on the elected cluster manager,
 * after the templates are written and the indices created, and before the readiness marker. A
 * stored template only applies to indices created afterwards, so after a package upgrade the
 * existing indices keep the mappings and settings of the previous version: the records say which
 * ones do, and whether they can be upgraded in place or must be rebuilt. The upgrades themselves
 * are run by later steps that read these records.
 *
 * <p>Detection reads version metadata only. It never compares live mappings or settings against the
 * shipped files.
 */
public class SchemaDriftDetector {
    private static final Logger log = LogManager.getLogger(SchemaDriftDetector.class);

    private final List<Index> indices;
    private final SetupStatusIndex statusIndex;

    /**
     * Constructor.
     *
     * @param indices every index the plugin manages. Those not taking part in the schema versioning
     *     ({@link Index#isVersioned()}) are skipped.
     * @param statusIndex the index holding the records.
     */
    public SchemaDriftDetector(List<Index> indices, SetupStatusIndex statusIndex) {
        this.indices = indices;
        this.statusIndex = statusIndex;
    }

    /**
     * Classifies every versioned index and writes its record.
     *
     * <p>A record that already exists for an index still pending keeps its {@code step}, so an
     * upgrade interrupted on a previous boot resumes where it stopped instead of restarting a step
     * already recorded as complete. The step is cleared once the index is up to date.
     *
     * @return the records written, one per versioned index.
     * @throws IllegalStateException if the template or the record of an index cannot be read or
     *     written. The message names the index.
     */
    public List<IndexRecord> detect() {
        List<IndexRecord> records = new ArrayList<>();
        for (Index index : this.indices) {
            if (!index.isVersioned()) {
                continue;
            }
            String name = index.getIndexName();
            try {
                records.add(this.detect(index));
            } catch (Exception e) {
                throw new IllegalStateException(
                        "Schema drift detection failed for index [" + name + "]: " + e.getMessage(), e);
            }
        }
        long pending = records.stream().filter(IndexRecord::isPending).count();
        if (pending == 0) {
            log.info("All {} managed indices are at the shipped schema version.", records.size());
        } else {
            log.warn("{} of {} managed indices need a schema upgrade.", pending, records.size());
        }
        return records;
    }

    /**
     * Classifies one index and writes its record.
     *
     * @param index the index.
     * @return the record written.
     * @throws IOException if the shipped template cannot be read.
     */
    private IndexRecord detect(Index index) throws IOException {
        String name = index.getIndexName();
        Map<String, Object> shipped = index.loadTemplate().getSchemaVersions();
        if (shipped == null) {
            throw new IllegalArgumentException("the shipped template declares no schema versions");
        }
        long shippedVersion = ((Number) shipped.get(IndexTemplate.SCHEMA_VERSION_KEY)).longValue();
        long compatVersion = ((Number) shipped.get(IndexTemplate.COMPAT_VERSION_KEY)).longValue();
        long installed = index.getInstalledSchemaVersion();

        // The step of an upgrade in progress survives the detection; it is dropped once the index
        // is up to date.
        Optional<IndexRecord> previous = this.statusIndex.getIndexRecord(name);
        String step = previous.map(IndexRecord::step).orElse(null);
        IndexRecord record = IndexRecord.of(name, installed, shippedVersion, compatVersion, step);
        if (record.isPending()) {
            log.warn(
                    "Index [{}] is at schema version {}, shipped {} (compatible from {}): {}{}",
                    name,
                    installed,
                    shippedVersion,
                    compatVersion,
                    record.status().getValue(),
                    step == null ? "" : ", resuming after step [" + step + "]");
        } else if (step != null) {
            record = IndexRecord.of(name, installed, shippedVersion, compatVersion, null);
        }
        if (installed > shippedVersion) {
            log.warn(
                    "Index [{}] is at schema version {}, newer than the shipped {}. Downgrades are not supported; the index is left as it is.",
                    name,
                    installed,
                    shippedVersion);
        }
        this.statusIndex.putIndexRecord(record);
        return record;
    }
}
