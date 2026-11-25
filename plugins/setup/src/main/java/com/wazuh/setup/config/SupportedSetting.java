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
package com.wazuh.setup.config;

import org.opensearch.cluster.metadata.IndexMetadata;
import org.opensearch.common.settings.Setting;
import org.opensearch.common.settings.Settings;
import org.opensearch.index.IndexSettings;

import java.util.List;

/**
 * Index settings that {@code setup.yml} can override in the index templates of the plugin. Any
 * other setting is rejected as an unknown key.
 *
 * <p>Four of them are checked with the definition OpenSearch itself uses, so the accepted values
 * are exactly the ones an index accepts. The codec and the translog durability are checked against
 * a list: the OpenSearch codec check depends on the codec plugins loaded in the node, and the
 * durability check reports a Java enum name instead of the valid values.
 *
 * <p>A value of those two lists must be written exactly as listed. The value goes to the index
 * template as it is written, and OpenSearch matches a codec by its exact name: {@code ZSTD} is not
 * {@code zstd} but an old codec that can only read, so an index created with it fails on its first
 * write.
 */
public enum SupportedSetting {
    /** Number of primary shards. */
    NUMBER_OF_SHARDS(IndexMetadata.INDEX_NUMBER_OF_SHARDS_SETTING),
    /** Number of replicas of each primary shard. */
    NUMBER_OF_REPLICAS(IndexMetadata.INDEX_NUMBER_OF_REPLICAS_SETTING),
    /** Range the number of replicas follows as data nodes join and leave. */
    AUTO_EXPAND_REPLICAS(IndexMetadata.INDEX_AUTO_EXPAND_REPLICAS_SETTING),
    /** How often new documents become searchable. */
    REFRESH_INTERVAL(IndexSettings.INDEX_REFRESH_INTERVAL_SETTING),
    /** Compression of the stored data. */
    CODEC("index.codec", "default", List.of("default", "best_compression", "zstd", "zstd_no_dict")),
    /** When a write is synced to disk. */
    TRANSLOG_DURABILITY("index.translog.durability", "request", List.of("request", "async"));

    private final Setting<?> setting;
    private final List<String> listedValues;

    SupportedSetting(Setting<?> setting) {
        this.setting = setting;
        this.listedValues = List.of();
    }

    SupportedSetting(String key, String defaultValue, List<String> listedValues) {
        this.setting = SupportedSetting.oneOf(key, defaultValue, listedValues);
        this.listedValues = listedValues;
    }

    /**
     * Returns the full name of the index setting.
     *
     * @return the setting key, for example {@code index.number_of_shards}.
     */
    public String key() {
        return this.setting.getKey();
    }

    /**
     * Returns the values this setting accepts when it is checked against a list.
     *
     * @return the accepted values, written as they must be written, or an empty list when the setting
     *     is checked with the definition of OpenSearch.
     */
    public List<String> listedValues() {
        return this.listedValues;
    }

    /**
     * Reads this setting from the given settings, in a form that compares equal for equal values
     * however they are written ({@code 2000ms} and {@code 2s}, for example). A setting that is not
     * present yields its OpenSearch default. The form is meant for comparing, not for messages: an
     * auto-expand range of {@code 0-all}, for example, reads as {@code 0-2147483647}.
     *
     * @param settings settings holding the full key of this setting.
     * @return the value of the setting.
     * @throws IllegalArgumentException if the value is not valid for the setting.
     */
    public String read(Settings settings) {
        return String.valueOf(this.setting.get(settings));
    }

    /**
     * Returns the supported setting with the given key.
     *
     * @param key full name of an index setting.
     * @return the supported setting, or null when the key is not one of them.
     */
    public static SupportedSetting fromKey(String key) {
        for (SupportedSetting supported : SupportedSetting.values()) {
            if (supported.key().equals(key)) {
                return supported;
            }
        }
        return null;
    }

    /**
     * Builds a setting that only accepts the listed values, written exactly as listed.
     *
     * @param key full name of the index setting.
     * @param defaultValue OpenSearch default of the setting.
     * @param values accepted values.
     * @return the setting definition.
     */
    private static Setting<String> oneOf(String key, String defaultValue, List<String> values) {
        return new Setting<>(
                key,
                defaultValue,
                value -> {
                    if (!values.contains(value)) {
                        throw new IllegalArgumentException(
                                "unknown value [" + value + "] for [" + key + "], must be one of " + values);
                    }
                    return value;
                },
                Setting.Property.IndexScope);
    }
}
