/*
 * Copyright (C) 2024, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.utils;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

import java.util.HashMap;
import java.util.Map;

/** Tests for the HashCalculator utility class. */
public class HashCalculatorTests extends OpenSearchTestCase {

    /** Tests that sha256 returns consistent hash for the same input. */
    public void testSha256ReturnsConsistentHash() {
        String payload = "test-payload";

        String hash1 = HashCalculator.sha256(payload);
        String hash2 = HashCalculator.sha256(payload);

        Assert.assertEquals(hash1, hash2);
        Assert.assertEquals(64, hash1.length()); // SHA-256 produces 64 hex characters
    }

    /** Tests that sha256 produces different hashes for different inputs. */
    public void testSha256DifferentInputsProduceDifferentHashes() {
        String payload1 = "test-payload-1";
        String payload2 = "test-payload-2";

        String hash1 = HashCalculator.sha256(payload1);
        String hash2 = HashCalculator.sha256(payload2);

        Assert.assertNotEquals(hash1, hash2);
    }

    /** Tests that sha256 returns the known hash for an empty string. */
    public void testSha256EmptyString() {
        String payload = "";

        String hash = HashCalculator.sha256(payload);

        // SHA-256 of empty string is a known value
        Assert.assertEquals("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", hash);
    }

    /** Tests that sha256 handles special characters correctly. */
    public void testSha256SpecialCharacters() {
        String payload = "test-with-special-chars-!@#$%^&*()";

        String hash = HashCalculator.sha256(payload);

        Assert.assertNotNull(hash);
        Assert.assertEquals(64, hash.length());
    }

    /** Tests that extractHash returns the sha256 value from a valid source map. */
    public void testExtractHashFromValidSource() {
        Map<String, Object> source = new HashMap<>();
        Map<String, Object> hashObj = new HashMap<>();
        hashObj.put("sha256", "abc123def456");
        source.put("hash", hashObj);

        String result = HashCalculator.extractHash(source);

        Assert.assertEquals("abc123def456", result);
    }

    /** Tests that extractHash returns empty string when hash field is missing. */
    public void testExtractHashFromSourceWithoutHashField() {
        Map<String, Object> source = new HashMap<>();
        source.put("other", "value");

        String result = HashCalculator.extractHash(source);

        Assert.assertEquals("", result);
    }

    /** Tests that extractHash returns empty string when hash object is empty. */
    public void testExtractHashFromSourceWithEmptyHashObject() {
        Map<String, Object> source = new HashMap<>();
        Map<String, Object> hashObj = new HashMap<>();
        source.put("hash", hashObj);

        String result = HashCalculator.extractHash(source);

        Assert.assertEquals("", result);
    }

    /** Tests that extractHash returns empty string when sha256 key is missing. */
    public void testExtractHashFromSourceWithMissingSha256() {
        Map<String, Object> source = new HashMap<>();
        Map<String, Object> hashObj = new HashMap<>();
        hashObj.put("md5", "somehash");
        source.put("hash", hashObj);

        String result = HashCalculator.extractHash(source);

        Assert.assertEquals("", result);
    }
}
