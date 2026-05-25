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
package com.wazuh.contentmanager.utils;

import org.opensearch.test.OpenSearchTestCase;

/** Unit tests for {@link UrlUtils}. */
public class UrlUtilsTests extends OpenSearchTestCase {

    public void testTrailingSlashDiffers() {
        // The reported bug: same logical resource, one has a trailing '/'.
        String a = "https://x/api/v1/catalog/contexts/c/consumers/u";
        String b = a + "/";
        assertTrue(UrlUtils.isSameResource(a, b));
        assertTrue(UrlUtils.isSameResource(b, a));
    }

    public void testIdentical() {
        String url = "https://x/y";
        assertTrue(UrlUtils.isSameResource(url, url));
    }

    public void testDifferentPath() {
        assertFalse(UrlUtils.isSameResource("https://x/a", "https://x/b"));
    }

    public void testSchemeCaseDiffers() {
        assertTrue(UrlUtils.isSameResource("HTTPS://x/y", "https://x/y"));
    }

    public void testHostCaseDiffers() {
        assertTrue(UrlUtils.isSameResource("https://X.com/y", "https://x.com/y"));
    }

    public void testPathCaseDiffersStays() {
        // Per RFC 3986 §6.2.2.1, path case is significant.
        assertFalse(UrlUtils.isSameResource("https://x/Y", "https://x/y"));
    }

    public void testQueryDiffers() {
        assertFalse(UrlUtils.isSameResource("https://x/y?a=1", "https://x/y?a=2"));
    }

    public void testRootPathSlash() {
        assertTrue(UrlUtils.isSameResource("https://x/", "https://x"));
    }

    public void testWhitespacePadding() {
        assertTrue(UrlUtils.isSameResource(" https://x/y ", "https://x/y"));
    }

    public void testMalformedBothSame() {
        // Malformed input falls back to trimmed literal equality.
        assertTrue(UrlUtils.isSameResource("not a url", "not a url"));
    }

    public void testMalformedVsValid() {
        assertFalse(UrlUtils.isSameResource("not a url", "https://x/y"));
    }

    public void testBothNull() {
        assertTrue(UrlUtils.isSameResource(null, null));
    }

    public void testOneNull() {
        assertFalse(UrlUtils.isSameResource(null, "https://x"));
        assertFalse(UrlUtils.isSameResource("https://x", null));
    }

    public void testBothBlank() {
        assertTrue(UrlUtils.isSameResource("  ", ""));
        assertTrue(UrlUtils.isSameResource("", null));
    }
}
