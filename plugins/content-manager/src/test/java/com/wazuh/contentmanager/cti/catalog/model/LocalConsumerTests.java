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

/** Unit tests for the {@link LocalConsumer} class. */
public class LocalConsumerTests extends OpenSearchTestCase {

    private final ObjectMapper mapper = new ObjectMapper();

    /** Tests that the two-arg constructor sets status to IDLE by default. */
    public void testDefaultStatusIsIdle() {
        LocalConsumer consumer = new LocalConsumer("ctx", "name");
        Assert.assertEquals(LocalConsumer.Status.IDLE, consumer.getStatus());
    }

    /** Tests that the five-arg constructor sets status to IDLE by default. */
    public void testFiveArgConstructorDefaultStatusIsIdle() {
        LocalConsumer consumer = new LocalConsumer("ctx", "name", 10L, 20L, "http://snapshot");
        Assert.assertEquals(LocalConsumer.Status.IDLE, consumer.getStatus());
    }

    /** Tests that the six-arg constructor sets the provided status. */
    public void testSixArgConstructorSetsStatus() {
        LocalConsumer consumer =
                new LocalConsumer(
                        "ctx", "name", LocalConsumer.Status.UPDATING, 10L, 20L, "http://snapshot");
        Assert.assertEquals(LocalConsumer.Status.UPDATING, consumer.getStatus());
    }

    /** Tests that toXContent serializes the status field. */
    public void testToXContentIncludesStatus() throws Exception {
        LocalConsumer consumer =
                new LocalConsumer("ctx", "name", LocalConsumer.Status.UPDATING, 5L, 10L, "http://snap");
        XContentBuilder builder = consumer.toXContent();
        String json = builder.toString();

        Assert.assertTrue(
                "status field must be present in serialized output", json.contains("\"status\""));
        Assert.assertTrue("status value must be 'updating'", json.contains("\"updating\""));
    }

    /** Tests that the status field round-trips through JSON deserialization. */
    public void testStatusDeserializationIdle() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"idle\","
                        + "\"local_offset\":0,\"remote_offset\":0,\"snapshot_link\":\"\"}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertEquals(LocalConsumer.Status.IDLE, consumer.getStatus());
    }

    /** Tests that the status field round-trips through JSON deserialization for UPDATING. */
    public void testStatusDeserializationUpdating() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\",\"status\":\"updating\","
                        + "\"local_offset\":0,\"remote_offset\":0,\"snapshot_link\":\"\"}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertEquals(LocalConsumer.Status.UPDATING, consumer.getStatus());
    }

    /** Tests that documents without a status field (legacy) deserialize without error. */
    public void testLegacyDocumentWithoutStatusDeserializesSuccessfully() throws Exception {
        String json =
                "{\"name\":\"name\",\"context\":\"ctx\","
                        + "\"local_offset\":5,\"remote_offset\":10,\"snapshot_link\":\"http://snap\"}";
        LocalConsumer consumer = this.mapper.readValue(json, LocalConsumer.class);
        Assert.assertNull(
                "status should be null for legacy documents without the field", consumer.getStatus());
        Assert.assertEquals(5L, consumer.getLocalOffset());
    }
}
