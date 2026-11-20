/*
 * Copyright (C) 2024-2026, Wazuh Inc.
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
package com.wazuh.contentmanager.action;

import com.fasterxml.jackson.databind.ObjectMapper;

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.common.xcontent.XContentFactory;
import org.opensearch.core.common.bytes.BytesReference;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.ToXContent;
import org.opensearch.core.xcontent.XContentBuilder;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;

import com.wazuh.contentmanager.cti.console.EnvironmentFixtures;

/** Unit tests for {@link GetSubscriptionResponse}. */
public class GetSubscriptionResponseTests extends OpenSearchTestCase {

    private static String toJson(GetSubscriptionResponse response) throws IOException {
        try (XContentBuilder builder = XContentFactory.jsonBuilder()) {
            response.toXContent(builder, ToXContent.EMPTY_PARAMS);
            return BytesReference.bytes(builder).utf8ToString();
        }
    }

    private static GetSubscriptionResponse roundTrip(GetSubscriptionResponse response)
            throws IOException {
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            response.writeTo(out);
            try (StreamInput in = out.bytes().streamInput()) {
                return new GetSubscriptionResponse(in);
            }
        }
    }

    /** The environment crosses the transport layer, so any node can answer. */
    public void testEnvironmentSurvivesTheWire() throws IOException {
        GetSubscriptionResponse response =
                new GetSubscriptionResponse(
                        "Pro",
                        false,
                        true,
                        new ObjectMapper().readTree(EnvironmentFixtures.REGISTERED).toString());

        Assert.assertEquals(
                GetSubscriptionResponseTests.toJson(response),
                GetSubscriptionResponseTests.toJson(GetSubscriptionResponseTests.roundTrip(response)));
    }

    /** Without an environment the field is left out, before and after the wire. */
    public void testNoEnvironmentLeavesTheFieldOut() throws IOException {
        String expected =
                "{\"message\":{\"plan\":{\"name\":\"Open\",\"is_public\":true},\"is_registered\":false},"
                        + "\"status\":200}";
        GetSubscriptionResponse response = new GetSubscriptionResponse("Open", true, false);

        Assert.assertEquals(expected, GetSubscriptionResponseTests.toJson(response));
        Assert.assertEquals(
                expected,
                GetSubscriptionResponseTests.toJson(GetSubscriptionResponseTests.roundTrip(response)));
    }

    /** An error answer is unchanged and still crosses the wire. */
    public void testErrorIsUnchanged() throws IOException {
        GetSubscriptionResponse response =
                new GetSubscriptionResponse("unavailable", RestStatus.BAD_GATEWAY);

        Assert.assertEquals(
                "{\"message\":\"unavailable\",\"status\":502}",
                GetSubscriptionResponseTests.toJson(response));
        Assert.assertEquals(
                GetSubscriptionResponseTests.toJson(response),
                GetSubscriptionResponseTests.toJson(GetSubscriptionResponseTests.roundTrip(response)));
    }

    /** The environment is written under {@code message.environment}, after the existing fields. */
    public void testEnvironmentIsWrittenAsGiven() throws IOException {
        String environment = "{\"name\":\"environment-01\",\"expires_at\":null,\"seats\":5}";

        Assert.assertEquals(
                "{\"message\":{\"plan\":{\"name\":\"Pro\",\"is_public\":false},\"is_registered\":true,"
                        + "\"environment\":"
                        + environment
                        + "},\"status\":200}",
                GetSubscriptionResponseTests.toJson(
                        new GetSubscriptionResponse("Pro", false, true, environment)));
    }

    /**
     * A pretty-printing builder cannot take raw JSON, so the environment is parsed and copied
     * instead: the content is the same.
     */
    public void testPrettyBuilderWritesTheSameEnvironment() throws IOException {
        GetSubscriptionResponse response =
                new GetSubscriptionResponse(
                        "Pro",
                        false,
                        true,
                        new ObjectMapper().readTree(EnvironmentFixtures.REGISTERED).toString());
        String pretty;
        try (XContentBuilder builder = XContentFactory.jsonBuilder().prettyPrint()) {
            response.toXContent(builder, ToXContent.EMPTY_PARAMS);
            pretty = BytesReference.bytes(builder).utf8ToString();
        }

        ObjectMapper mapper = new ObjectMapper();
        Assert.assertEquals(
                mapper.readTree(GetSubscriptionResponseTests.toJson(response)), mapper.readTree(pretty));
        Assert.assertNotEquals(GetSubscriptionResponseTests.toJson(response), pretty);
    }
}
