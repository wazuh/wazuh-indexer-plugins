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
package com.wazuh.setup.model;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Schema version record of one index the Setup plugin manages, as stored in the {@code
 * .wazuh-setup-status} index.
 *
 * <p>The record names the index, the schema version it carries ({@code installed}), the versions
 * the shipped template declares ({@code shipped} and {@code compat}), the resulting {@link
 * SchemaStatus}, and the last step an upgrade in progress completed ({@code step}, absent when no
 * upgrade is in progress). The step lets an interrupted upgrade resume on the next boot instead of
 * starting over.
 */
public record IndexRecord(
        String index,
        long installed,
        long shipped,
        long compat,
        SchemaStatus status,
        String step,
        Instant updatedAt) {

    /** JSON key of the index name. */
    public static final String KEY_INDEX = "index";

    /** JSON key of the schema version the index carries. */
    public static final String KEY_INSTALLED = "installed";

    /** JSON key of the schema version of the shipped template. */
    public static final String KEY_SHIPPED = "shipped";

    /** JSON key of the compatibility version of the shipped template. */
    public static final String KEY_COMPAT = "compat";

    /** JSON key of the status. */
    public static final String KEY_STATUS = "status";

    /** JSON key of the last completed upgrade step. */
    public static final String KEY_STEP = "step";

    /** JSON key of the time the record was last written. */
    public static final String KEY_UPDATED_AT = "updated_at";

    /**
     * Constructor.
     *
     * @param index name of the index, data stream or alias.
     * @param installed schema version the index carries, {@code 0} when it carries none.
     * @param shipped schema version of the shipped template.
     * @param compat compatibility version of the shipped template.
     * @param status status of the index.
     * @param step last completed upgrade step, or null when no upgrade is in progress.
     * @param updatedAt time the record was written.
     */
    public IndexRecord(
            String index,
            long installed,
            long shipped,
            long compat,
            SchemaStatus status,
            String step,
            Instant updatedAt) {
        this.index = Objects.requireNonNull(index);
        this.installed = installed;
        this.shipped = shipped;
        this.compat = compat;
        this.status = Objects.requireNonNull(status);
        this.step = step;
        this.updatedAt = Objects.requireNonNull(updatedAt);
    }

    /**
     * Builds the record of an index from its versions, classifying it on the way.
     *
     * @param index name of the index, data stream or alias.
     * @param installed schema version the index carries, {@code 0} when it carries none.
     * @param shipped schema version of the shipped template.
     * @param compat compatibility version of the shipped template.
     * @param step last completed upgrade step, or null when no upgrade is in progress.
     * @return the record, dated now.
     */
    public static IndexRecord of(
            String index, long installed, long shipped, long compat, String step) {
        return new IndexRecord(
                index,
                installed,
                shipped,
                compat,
                SchemaStatus.classify(installed, shipped, compat),
                step,
                Instant.now());
    }

    /**
     * Reads a record from its stored form.
     *
     * @param source the document source.
     * @return the record.
     * @throws IllegalArgumentException if a required field is missing or malformed.
     */
    public static IndexRecord fromMap(Map<String, Object> source) {
        Object index = source.get(KEY_INDEX);
        Object status = source.get(KEY_STATUS);
        Object updatedAt = source.get(KEY_UPDATED_AT);
        if (!(index instanceof String)
                || !(status instanceof String)
                || !(updatedAt instanceof String)) {
            throw new IllegalArgumentException("Malformed index record: " + source);
        }
        Object step = source.get(KEY_STEP);
        return new IndexRecord(
                (String) index,
                IndexRecord.number(source, KEY_INSTALLED),
                IndexRecord.number(source, KEY_SHIPPED),
                IndexRecord.number(source, KEY_COMPAT),
                SchemaStatus.fromValue((String) status),
                step instanceof String ? (String) step : null,
                Instant.parse((String) updatedAt));
    }

    private static long number(Map<String, Object> source, String key) {
        Object value = source.get(key);
        if (!(value instanceof Number)) {
            throw new IllegalArgumentException(
                    "Malformed index record: [" + key + "] is not a number in " + source);
        }
        return ((Number) value).longValue();
    }

    /**
     * Returns the stored form of the record. The step is left out when there is none.
     *
     * @return the document source.
     */
    public Map<String, Object> toMap() {
        Map<String, Object> source = new HashMap<>();
        source.put(KEY_INDEX, this.index);
        source.put(KEY_INSTALLED, this.installed);
        source.put(KEY_SHIPPED, this.shipped);
        source.put(KEY_COMPAT, this.compat);
        source.put(KEY_STATUS, this.status.getValue());
        if (this.step != null) {
            source.put(KEY_STEP, this.step);
        }
        source.put(KEY_UPDATED_AT, this.updatedAt.toString());
        return source;
    }

    /**
     * Returns whether the index still needs an upgrade.
     *
     * @return true unless the status is {@link SchemaStatus#UP_TO_DATE}.
     */
    public boolean isPending() {
        return this.status != SchemaStatus.UP_TO_DATE;
    }

    /**
     * Index name getter.
     *
     * @return name of the index, data stream or alias.
     */
    @Override
    public String index() {
        return this.index;
    }

    /**
     * Installed version getter.
     *
     * @return schema version the index carries, {@code 0} when it carries none.
     */
    @Override
    public long installed() {
        return this.installed;
    }

    /**
     * Shipped version getter.
     *
     * @return schema version of the shipped template.
     */
    @Override
    public long shipped() {
        return this.shipped;
    }

    /**
     * Compatibility version getter.
     *
     * @return compatibility version of the shipped template.
     */
    @Override
    public long compat() {
        return this.compat;
    }

    /**
     * Status getter.
     *
     * @return status of the index.
     */
    @Override
    public SchemaStatus status() {
        return this.status;
    }

    /**
     * Step getter.
     *
     * @return last completed upgrade step, or null when no upgrade is in progress.
     */
    @Override
    public String step() {
        return this.step;
    }

    /**
     * Update time getter.
     *
     * @return time the record was written.
     */
    @Override
    public Instant updatedAt() {
        return this.updatedAt;
    }

    @Override
    public String toString() {
        return "IndexRecord{"
                + "index="
                + this.index
                + ", installed="
                + this.installed
                + ", shipped="
                + this.shipped
                + ", compat="
                + this.compat
                + ", status="
                + this.status.getValue()
                + ", step="
                + this.step
                + '}';
    }
}
