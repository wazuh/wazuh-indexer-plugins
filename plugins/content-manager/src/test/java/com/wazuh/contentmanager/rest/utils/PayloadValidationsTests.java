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
package com.wazuh.contentmanager.rest.utils;

import org.opensearch.common.settings.Settings;
import org.opensearch.common.util.concurrent.ThreadContext;
import org.opensearch.core.common.bytes.BytesArray;
import org.opensearch.core.rest.RestStatus;
import org.opensearch.core.xcontent.NamedXContentRegistry;
import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.opensearch.test.rest.FakeRestRequest;
import org.junit.Assert;

import com.wazuh.contentmanager.action.LogtestResponse;

public class PayloadValidationsTests extends OpenSearchTestCase {

    private RestRequest requestWithBody(int bytes) {
        return new FakeRestRequest.Builder(NamedXContentRegistry.EMPTY)
                .withContent(new BytesArray(new byte[bytes]), null)
                .withPath("/_plugins/_content_manager/logtest")
                .build();
    }

    public void testValidateLogtestBodySize_underLimitReturnsNull() {
        ThreadContext ctx = new ThreadContext(Settings.EMPTY);
        LogtestResponse result =
                PayloadValidations.validateLogtestBodySize(requestWithBody(512), 1024, ctx);
        Assert.assertNull(result);
    }

    public void testValidateLogtestBodySize_atLimitReturnsNull() {
        ThreadContext ctx = new ThreadContext(Settings.EMPTY);
        LogtestResponse result =
                PayloadValidations.validateLogtestBodySize(requestWithBody(1024), 1024, ctx);
        Assert.assertNull(result);
    }

    public void testValidateLogtestBodySize_overLimitReturns413() {
        ThreadContext ctx = new ThreadContext(Settings.EMPTY);
        LogtestResponse result =
                PayloadValidations.validateLogtestBodySize(requestWithBody(2048), 1024, ctx);
        Assert.assertNotNull(result);
        Assert.assertEquals(RestStatus.REQUEST_ENTITY_TOO_LARGE, result.getStatus());
    }

    public void testValidateLogtestBodySize_nullThreadContextDoesNotThrow() {
        LogtestResponse result =
                PayloadValidations.validateLogtestBodySize(requestWithBody(2048), 1024, null);
        Assert.assertNotNull(result);
        Assert.assertEquals(RestStatus.REQUEST_ENTITY_TOO_LARGE, result.getStatus());
    }
}
