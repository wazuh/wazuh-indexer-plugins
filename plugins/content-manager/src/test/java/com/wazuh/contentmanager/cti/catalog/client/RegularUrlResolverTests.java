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
package com.wazuh.contentmanager.cti.catalog.client;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

/**
 * Unit tests for {@link RegularUrlResolver}. Verifies that the resolver returns the original URL
 * unchanged.
 */
public class RegularUrlResolverTests extends OpenSearchTestCase {

    /** Tests that resolve returns the exact same URL that was passed in. */
    public void testResolveReturnsOriginalUrl() {
        RegularUrlResolver resolver = new RegularUrlResolver();
        String url = "https://cti.wazuh.com/catalog/contexts/wazuh/consumers/ruleset";

        Assert.assertEquals(url, resolver.resolve(url));
    }

    /** Tests that resolve handles a URL with query parameters. */
    public void testResolvePreservesQueryParameters() {
        RegularUrlResolver resolver = new RegularUrlResolver();
        String url =
                "https://cti.wazuh.com/catalog/contexts/wazuh/consumers/ruleset/changes?from_offset=0&to_offset=100";

        Assert.assertEquals(url, resolver.resolve(url));
    }

    /** Tests that resolve handles null input without transformation. */
    public void testResolveWithNull() {
        RegularUrlResolver resolver = new RegularUrlResolver();

        Assert.assertNull(resolver.resolve(null));
    }
}
