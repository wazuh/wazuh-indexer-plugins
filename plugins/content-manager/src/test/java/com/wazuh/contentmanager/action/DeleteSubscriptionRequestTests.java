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

import org.opensearch.common.io.stream.BytesStreamOutput;
import org.opensearch.core.common.io.stream.StreamInput;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.io.IOException;

public class DeleteSubscriptionRequestTests extends OpenSearchTestCase {

    public void testDeletionRequest_isNotPermissionCheckOnly() {
        Assert.assertFalse(new DeleteSubscriptionRequest().isPermissionCheckOnly());
    }

    public void testPermissionCheck_isFlagged() {
        Assert.assertTrue(DeleteSubscriptionRequest.permissionCheck().isPermissionCheckOnly());
    }

    /**
     * {@code TransportAction.execute} validates before running the {@code ActionFilters} chain, so a
     * permission check that failed validation would never reach the security filter.
     */
    public void testValidate_bothShapesAreValid() {
        Assert.assertNull(new DeleteSubscriptionRequest().validate());
        Assert.assertNull(DeleteSubscriptionRequest.permissionCheck().validate());
    }

    public void testSerialization_deletionRoundTrip() throws IOException {
        assertRoundTrip(new DeleteSubscriptionRequest(), false);
    }

    public void testSerialization_permissionCheckRoundTrip() throws IOException {
        assertRoundTrip(DeleteSubscriptionRequest.permissionCheck(), true);
    }

    private void assertRoundTrip(DeleteSubscriptionRequest request, boolean expectedCheckOnly)
            throws IOException {
        try (BytesStreamOutput out = new BytesStreamOutput()) {
            request.writeTo(out);
            try (StreamInput in = out.bytes().streamInput()) {
                DeleteSubscriptionRequest read = new DeleteSubscriptionRequest(in);
                Assert.assertEquals(expectedCheckOnly, read.isPermissionCheckOnly());
                Assert.assertEquals(0, in.available());
            }
        }
    }
}
