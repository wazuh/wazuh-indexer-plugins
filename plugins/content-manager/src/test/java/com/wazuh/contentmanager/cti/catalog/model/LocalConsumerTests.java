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

import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.util.List;

/** Unit tests for the {@link LocalConsumer} class. */
public class LocalConsumerTests extends OpenSearchTestCase {

    private final ObjectMapper mapper = new ObjectMapper();

    /** Tests that the metadata constructor sets status to RUNNING by default. */
    public void testDefaultStatusIsRunning() {
        LocalConsumer consumer =
                new LocalConsumer("ctx", "name", "cti:catalog:consumer:ruleset", "https://cti/rules", true);
        Assert.assertEquals(LocalConsumer.Status.RUNNING, consumer.getStatus());
    }

    /** Tests that the offsets constructor sets status to RUNNING by default. */
    public void testOffsetsConstructorDefaultStatusIsRunning() {
        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx", "name", "cti:catalog:consumer:ruleset", "https://cti/rules", false, 10L, 20L);
        Assert.assertEquals(LocalConsumer.Status.RUNNING, consumer.getStatus());
    }

    /** Tests that the status constructor sets the provided status. */
    public void testStatusConstructorSetsStatus() {
        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx",
                        "name",
                        "cti:catalog:consumer:ruleset",
                        "https://cti/rules",
                        true,
                        LocalConsumer.Status.RUNNING,
                        10L,
                        20L);
        Assert.assertEquals(LocalConsumer.Status.RUNNING, consumer.getStatus());
    }

    /** Tests that toXContent serializes the status field. */
    public void testToXContentIncludesStatus() throws Exception {
        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx",
                        "name",
                        "cti:catalog:consumer:ruleset",
                        "https://cti/rules",
                        true,
                        LocalConsumer.Status.RUNNING,
                        5L,
                        10L);
        XContentBuilder builder = consumer.toXContent();
        String json = builder.toString();

        Assert.assertTrue(
                "status field must be present in serialized output", json.contains("\"status\""));
        Assert.assertTrue("status value must be 'running'", json.contains("\"running\""));
    }

    /** Tests that the status field round-trips through JSON deserialization for READY. */
    public void testStatusDeserializationReady() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"ready\","
                        + "\"type\":\"cti:catalog:consumer:iocs\","
                        + "\"resource\":\"https://cti/iocs\",\"is_public\":true,"
                        + "\"local_offset\":0,\"remote_offset\":0}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertEquals(LocalConsumer.Status.READY, consumer.getStatus());
    }

    /** Tests that the status field round-trips through JSON deserialization for RUNNING. */
    public void testStatusDeserializationRunning() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"running\","
                        + "\"type\":\"cti:catalog:consumer:iocs\","
                        + "\"resource\":\"https://cti/iocs\",\"is_public\":true,"
                        + "\"local_offset\":0,\"remote_offset\":0}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertEquals(LocalConsumer.Status.RUNNING, consumer.getStatus());
    }

    /** Tests that documents without a status field (legacy) deserialize without error. */
    public void testLegacyDocumentWithoutStatusDeserializesSuccessfully() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\","
                        + "\"type\":\"cti:catalog:consumer:iocs\","
                        + "\"resource\":\"https://cti/iocs\",\"is_public\":true,"
                        + "\"local_offset\":5,\"remote_offset\":10}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertNull(
                "status should be null for legacy documents without the field", consumer.getStatus());
        Assert.assertEquals(5L, consumer.getLocalOffset());
    }

    /** Tests that the status field round-trips through JSON deserialization for FAILED. */
    public void testStatusDeserializationFailed() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"failed\","
                        + "\"type\":\"cti:catalog:consumer:iocs\","
                        + "\"resource\":\"https://cti/iocs\",\"is_public\":true,"
                        + "\"local_offset\":0,\"remote_offset\":0}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertEquals(LocalConsumer.Status.FAILED, consumer.getStatus());
    }

    /** Tests that pendingSyncPhases defaults to an empty list on the offsets/status constructor. */
    public void testPendingSyncPhasesDefaultsEmpty() {
        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx",
                        "name",
                        "cti:catalog:consumer:ruleset",
                        "https://cti/rules",
                        true,
                        LocalConsumer.Status.RUNNING,
                        10L,
                        20L);
        Assert.assertTrue(consumer.getPendingSyncPhases().isEmpty());
    }

    /** Tests that toXContent serializes the pending_sync_phases field. */
    public void testToXContentIncludesPendingSyncPhases() throws Exception {
        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx",
                        "name",
                        "cti:catalog:consumer:ruleset",
                        "https://cti/rules",
                        true,
                        LocalConsumer.Status.RUNNING,
                        5L,
                        10L,
                        List.of("integrations", "detectors"));
        XContentBuilder builder = consumer.toXContent();
        String json = builder.toString();

        Assert.assertTrue(
                "pending_sync_phases field must be present in serialized output",
                json.contains("\"pending_sync_phases\""));
        Assert.assertTrue(json.contains("\"integrations\""));
        Assert.assertTrue(json.contains("\"detectors\""));
    }

    /** Tests that the pending_sync_phases field round-trips through JSON deserialization. */
    public void testPendingSyncPhasesDeserializesFromJson() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"ready\","
                        + "\"type\":\"cti:catalog:consumer:ruleset\","
                        + "\"resource\":\"https://cti/rules\",\"is_public\":true,"
                        + "\"local_offset\":0,\"remote_offset\":0,"
                        + "\"pending_sync_phases\":[\"detectors\"]}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertEquals(List.of("detectors"), consumer.getPendingSyncPhases());
    }

    /** Tests that documents without a pending_sync_phases field (legacy) deserialize to an empty list. */
    public void testLegacyDocumentWithoutPendingSyncPhasesDefaultsEmpty() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\","
                        + "\"type\":\"cti:catalog:consumer:iocs\","
                        + "\"resource\":\"https://cti/iocs\",\"is_public\":true,"
                        + "\"local_offset\":5,\"remote_offset\":10}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertTrue(
                "pending_sync_phases should default to empty for legacy documents",
                consumer.getPendingSyncPhases().isEmpty());
    }
}
