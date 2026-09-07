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
package com.wazuh.contentmanager.action;

import org.opensearch.action.ActionRequestValidationException;
import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;

public class IndexSubscriptionRequestTests extends OpenSearchTestCase {

    // --- registration requests: unchanged behaviour ------------------------------

    public void testRegistrationRequest_isNotPermissionCheckOnly() {
        IndexSubscriptionRequest request = new IndexSubscriptionRequest("a-token");
        Assert.assertFalse(request.isPermissionCheckOnly());
        Assert.assertEquals("a-token", request.getToken());
    }

    public void testRegistrationRequest_validTokenPassesValidation() {
        Assert.assertNull(new IndexSubscriptionRequest("a-token").validate());
    }

    public void testRegistrationRequest_nullTokenFailsValidation() {
        ActionRequestValidationException e = new IndexSubscriptionRequest((String) null).validate();
        Assert.assertNotNull(e);
        Assert.assertTrue(e.getMessage().contains("Missing [access_token] field."));
    }

    public void testRegistrationRequest_blankTokenFailsValidation() {
        ActionRequestValidationException e = new IndexSubscriptionRequest("   ").validate();
        Assert.assertNotNull(e);
        Assert.assertTrue(e.getMessage().contains("Missing [access_token] field."));
    }

    // --- permission-check requests ----------------------------------------------

    public void testPermissionCheck_carriesNoTokenAndIsFlagged() {
        IndexSubscriptionRequest request = IndexSubscriptionRequest.permissionCheck();
        Assert.assertTrue(request.isPermissionCheckOnly());
        Assert.assertNull(request.getToken());
    }

    /**
     * Load-bearing: {@code TransportAction.execute} validates before running the {@code
     * ActionFilters} chain, so a permission check that failed validation would be answered 400 and
     * the security filter would never evaluate it.
     */
    public void testPermissionCheck_skipsTokenValidation() {
        Assert.assertNull(IndexSubscriptionRequest.permissionCheck().validate());
    }

    // --- wire format -------------------------------------------------------------

    public void testSerialization_registrationRoundTrip() throws IOException {
        assertRoundTrip(new IndexSubscriptionRequest("a-token"), "a-token", false);
    }

    public void testSerialization_permissionCheckRoundTrip() throws IOException {
        assertRoundTrip(IndexSubscriptionRequest.permissionCheck(), null, true);
    }

    public void testSerialization_nullTokenRoundTrip() throws IOException {
        assertRoundTrip(new IndexSubscriptionRequest((String) null), null, false);
    }

    private void assertRoundTrip(
            IndexSubscriptionRequest request, String expectedToken, boolean expectedCheckOnly)
            throws IOException {
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            request.writeTo(out);
            try (StreamInput in = out.bytes().streamInput()) {
                IndexSubscriptionRequest read = new IndexSubscriptionRequest(in);
                Assert.assertEquals(expectedToken, read.getToken());
                Assert.assertEquals(expectedCheckOnly, read.isPermissionCheckOnly());
                Assert.assertEquals(0, in.available());
            }
        }
    }
}
