package com.wazuh.contentmanager.cti.catalog.utils;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * Utility class for SHA-256 hash calculations.
 */
public final class HashCalculator {
    private static final Logger log = LogManager.getLogger(HashCalculator.class);

    private HashCalculator() {}

    /**
     * Computes SHA-256 hash of a list of strings concatenated.
     */
    public static String sha256(String payload) {
        try {
            byte[] hash = MessageDigest
                .getInstance("SHA-256")
                .digest(payload.getBytes(StandardCharsets.UTF_8));

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
     * Helper to extract sha256 hash from document source.
     */
    public static String extractHash(Map<String, Object> source) {
        if (source.containsKey("hash")) {
            Map<String, Object> hashObj = (Map<String, Object>) source.get("hash");
            return (String) hashObj.getOrDefault("sha256", "");
        }
        return "";
    }
}