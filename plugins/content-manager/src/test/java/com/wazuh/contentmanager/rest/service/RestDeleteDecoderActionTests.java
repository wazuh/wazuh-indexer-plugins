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
package com.wazuh.contentmanager.rest.service;

import org.opensearch.rest.RestRequest;
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;
import org.junit.Before;

import com.wazuh.contentmanager.settings.PluginSettings;

public class RestDeleteDecoderActionTests extends OpenSearchTestCase {
    private RestDeleteDecoderAction action;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.action = new RestDeleteDecoderAction();
    }

    public void testRouteMethod() {
        Assert.assertEquals(1, this.action.routes().size());
        Assert.assertEquals(RestRequest.Method.DELETE, this.action.routes().get(0).getMethod());
    }

    public void testRoutePath() {
        Assert.assertEquals(PluginSettings.DECODERS_URI + "/{id}", this.action.routes().get(0).getPath());
    }

    public void testName() {
        Assert.assertEquals("content_manager_decoder_delete", this.action.getName());
    }
}
