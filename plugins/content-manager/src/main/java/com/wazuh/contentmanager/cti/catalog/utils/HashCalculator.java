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

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

/**
 * Utility class for SHA-256 hash calculations. Provides methods to compute hashes for content
 * integrity verification and to extract hash values from document sources.
 */
public final class HashCalculator {
    private static final Logger log = LogManager.getLogger(HashCalculator.class);

    private HashCalculator() {}

    /**
     * Computes the SHA-256 hash of a string payload.
     *
     * @param payload The string content to hash.
     * @return The hexadecimal representation of the SHA-256 hash, or an empty string if hashing
     *     fails.
     */
    public static String sha256(String payload) {
        try {
            byte[] hash =
                    MessageDigest.getInstance("SHA-256").digest(payload.getBytes(StandardCharsets.UTF_8));

            StringBuilder hexString = new StringBuilder(2 * hash.length);
            for (byte b : hash) {
                String hex = Integer.toHexString(0xff & b);
                if (hex.length() == 1) {
                    hexString.append('0');
                }
                hexString.append(hex);
            }
            return hexString.toString();
        } catch (NoSuchAlgorithmException e) {
            log.error("Error hashing content", e);
            return "";
        }
    }

    /**
     * Extracts the SHA-256 hash value from a document source map. Looks for a nested "hash" object
     * containing a "sha256" field.
     *
     * @param source The document source as a map.
     * @return The SHA-256 hash string if present, or an empty string if not found.
     */
    @SuppressWarnings("unchecked")
    public static String extractHash(Map<String, Object> source) {
        if (source.containsKey("hash")) {
            Map<String, Object> hashObj = (Map<String, Object>) source.get("hash");
            return (String) hashObj.getOrDefault("sha256", "");
        }
        return "";
    }
}
