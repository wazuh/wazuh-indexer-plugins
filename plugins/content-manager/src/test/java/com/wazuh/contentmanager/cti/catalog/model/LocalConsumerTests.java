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

import org.opensearch.common.xcontent.XContentHelper;
import org.opensearch.common.xcontent.XContentType;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.util.List;
import java.util.Map;

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

    /**
     * Tests that documents without a pending_sync_phases field (legacy) deserialize to an empty list.
     */
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

    /** Tests that updated_at is serialized when set and left out when there is none. */
    public void testToXContentWritesUpdatedAtOnlyWhenSet() throws Exception {
        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx",
                        "name",
                        "cti:catalog:consumer:iocs",
                        "https://cti/iocs",
                        true,
                        LocalConsumer.Status.READY,
                        5L,
                        5L);

        Assert.assertFalse(consumer.toXContent().toString().contains("updated_at"));
        Assert.assertTrue(
                consumer
                        .withUpdatedAt("2026-10-21T12:26:16.581Z")
                        .toXContent()
                        .toString()
                        .contains("\"updated_at\":\"2026-10-21T12:26:16.581Z\""));
    }

    /** Tests that updated_at round-trips through JSON, and is null for documents without it. */
    public void testUpdatedAtDeserialization() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"ready\","
                        + "\"type\":\"cti:catalog:consumer:iocs\","
                        + "\"resource\":\"https://cti/iocs\",\"is_public\":true,"
                        + "\"local_offset\":5,\"remote_offset\":5";
        Assert.assertEquals(
                "2026-10-21T12:26:16.581Z",
                this.mapper
                        .readValue(json + ",\"updated_at\":\"2026-10-21T12:26:16.581Z\"}", LocalConsumer.class)
                        .getUpdatedAt());
        Assert.assertNull(this.mapper.readValue(json + "}", LocalConsumer.class).getUpdatedAt());
    }

    /** Tests that withUpdatedAt copies every other field and leaves the original unchanged. */
    public void testWithUpdatedAtCopiesTheOtherFields() {
        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx",
                        "name",
                        "cti:catalog:consumer:ruleset",
                        "https://cti/rules",
                        false,
                        LocalConsumer.Status.FAILED,
                        10L,
                        20L,
                        List.of("rules"));

        LocalConsumer copy = consumer.withUpdatedAt("2026-10-21T12:26:16.581Z");

        Assert.assertEquals("2026-10-21T12:26:16.581Z", copy.getUpdatedAt());
        Assert.assertNull(consumer.getUpdatedAt());
        Assert.assertEquals(consumer.getContext(), copy.getContext());
        Assert.assertEquals(consumer.getName(), copy.getName());
        Assert.assertEquals(consumer.getType(), copy.getType());
        Assert.assertEquals(consumer.getResource(), copy.getResource());
        Assert.assertEquals(consumer.isPublic(), copy.isPublic());
        Assert.assertEquals(consumer.getStatus(), copy.getStatus());
        Assert.assertEquals(consumer.getLocalOffset(), copy.getLocalOffset());
        Assert.assertEquals(consumer.getRemoteOffset(), copy.getRemoteOffset());
        Assert.assertEquals(consumer.getPendingSyncPhases(), copy.getPendingSyncPhases());
    }

    /**
     * A ruleset document whose two nodes failed to load it, as the Engine content loader leaves it.
     */
    private static final String RULESET_WITH_FAILURES =
            "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"ready\","
                    + "\"type\":\"cti:catalog:consumer:ruleset\",\"resource\":\"https://cti/rules\","
                    + "\"is_public\":true,\"local_offset\":10,\"remote_offset\":10,"
                    + "\"pending_sync_phases\":[\"rules\",\"engine_load\"],"
                    + "\"engine_load_error\":{\"failed_at\":\"2025-11-23T06:47:13.000Z\",\"reason\":\"unreachable\","
                    + "\"message\":\"down\",\"node\":\"node-2\",\"nodes\":{"
                    + "\"id-1\":{\"failed_at\":\"2025-11-23T06:47:12.000Z\",\"reason\":\"refused\","
                    + "\"message\":\"Field is not defined in WCS schema\",\"node\":\"node-1\"},"
                    + "\"id-2\":{\"failed_at\":\"2025-11-23T06:47:13.000Z\",\"reason\":\"unreachable\","
                    + "\"message\":\"down\",\"node\":\"node-2\"}}}}";

    private static LocalConsumer ruleset(List<String> phases) {
        return new LocalConsumer(
                "ctx",
                "name",
                "cti:catalog:consumer:ruleset",
                "https://cti/rules",
                true,
                LocalConsumer.Status.READY,
                10L,
                10L,
                phases);
    }

    private static EngineLoadFailure failure(String failedAt, String node) {
        return new EngineLoadFailure(
                failedAt, EngineLoadFailure.REASON_REFUSED, "refused by " + node, node);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> written(LocalConsumer consumer) throws Exception {
        return XContentHelper.convertToMap(
                        BytesReference.bytes(consumer.toXContent()), false, XContentType.JSON)
                .v2();
    }

    /**
     * The Engine load state is read from engine_load_error.nodes; engine_load is not a
     * synchronization phase, so it is kept out of the phases the synchronization works with.
     */
    public void testEngineLoadFailuresDeserializeApartFromTheSyncPhases() throws Exception {
        LocalConsumer consumer = this.mapper.readValue(RULESET_WITH_FAILURES, LocalConsumer.class);

        Assert.assertEquals(List.of("rules"), consumer.getPendingSyncPhases());
        Assert.assertEquals(
                List.of("id-1", "id-2"), List.copyOf(consumer.getEngineLoadFailures().keySet()));
        Assert.assertEquals(
                EngineLoadFailure.REASON_REFUSED, consumer.getEngineLoadFailures().get("id-1").getReason());
    }

    /**
     * While a node has a failure recorded, the document lists engine_load after the synchronization
     * phases, and engine_load_error shows the most recent failure with every node's under nodes.
     */
    @SuppressWarnings("unchecked")
    public void testEngineLoadFailuresRoundTrip() throws Exception {
        LocalConsumer consumer = this.mapper.readValue(RULESET_WITH_FAILURES, LocalConsumer.class);

        Map<String, Object> source = LocalConsumerTests.written(consumer);

        Assert.assertEquals(
                List.of("rules", LocalConsumer.PHASE_ENGINE_LOAD), source.get("pending_sync_phases"));
        Map<String, Object> error = (Map<String, Object>) source.get("engine_load_error");
        Assert.assertEquals("2025-11-23T06:47:13.000Z", error.get("failed_at"));
        Assert.assertEquals(EngineLoadFailure.REASON_UNREACHABLE, error.get("reason"));
        Assert.assertEquals("down", error.get("message"));
        Assert.assertEquals("node-2", error.get("node"));
        Map<String, Object> nodes = (Map<String, Object>) error.get("nodes");
        Assert.assertEquals(
                Map.of(
                        "failed_at", "2025-11-23T06:47:12.000Z",
                        "reason", "refused",
                        "message", "Field is not defined in WCS schema",
                        "node", "node-1"),
                nodes.get("id-1"));
        Assert.assertEquals(
                consumer.getEngineLoadFailures(),
                this.mapper
                        .readValue(consumer.toXContent().toString(), LocalConsumer.class)
                        .getEngineLoadFailures());
    }

    /** With no failure recorded, neither engine_load nor engine_load_error is written. */
    public void testNoEngineLoadStateIsWrittenWithoutFailures() throws Exception {
        Map<String, Object> source =
                LocalConsumerTests.written(LocalConsumerTests.ruleset(List.of("rules")));

        Assert.assertEquals(List.of("rules"), source.get("pending_sync_phases"));
        Assert.assertFalse(source.containsKey("engine_load_error"));
    }

    /**
     * engine_load is derived from the recorded failures: a phase list that names it, with no failure
     * behind it, does not keep it.
     */
    public void testEngineLoadPhaseWithoutFailuresIsDropped() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"ready\","
                        + "\"type\":\"cti:catalog:consumer:ruleset\",\"resource\":\"https://cti/rules\","
                        + "\"is_public\":true,\"local_offset\":0,\"remote_offset\":0,"
                        + "\"pending_sync_phases\":[\"engine_load\"]}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);

        Assert.assertTrue(consumer.getPendingSyncPhases().isEmpty());
        Assert.assertEquals(List.of(), LocalConsumerTests.written(consumer).get("pending_sync_phases"));
        Assert.assertTrue(
                LocalConsumerTests.ruleset(List.of(LocalConsumer.PHASE_ENGINE_LOAD))
                        .getPendingSyncPhases()
                        .isEmpty());
    }

    /** The failure shown is the latest; a tie goes to the lowest node id, so every writer agrees. */
    public void testEngineLoadErrorIsTheLatestFailure() {
        LocalConsumer consumer =
                LocalConsumerTests.ruleset(List.of())
                        .withEngineLoadFailures(
                                Map.of(
                                        "id-b", LocalConsumerTests.failure("2025-11-23T06:47:12Z", "node-b"),
                                        "id-a", LocalConsumerTests.failure("2025-11-23T06:47:12.000Z", "node-a"),
                                        "id-c", LocalConsumerTests.failure("2025-11-23T06:40:00.000Z", "node-c")));

        Assert.assertEquals("node-a", consumer.getEngineLoadError().getNode());
        Assert.assertNull(LocalConsumerTests.ruleset(List.of()).getEngineLoadError());
    }

    /** Copies keep the failures, and withEngineLoadFailures replaces them. */
    public void testCopiesCarryTheEngineLoadFailures() {
        Map<String, EngineLoadFailure> failures =
                Map.of("id-1", LocalConsumerTests.failure("2025-11-23T06:47:12.000Z", "node-1"));
        LocalConsumer consumer = LocalConsumerTests.ruleset(List.of()).withEngineLoadFailures(failures);

        Assert.assertEquals(
                failures, consumer.withUpdatedAt("2025-11-23T07:00:00.000Z").getEngineLoadFailures());
        Assert.assertTrue(consumer.withEngineLoadFailures(null).getEngineLoadFailures().isEmpty());
    }
}
