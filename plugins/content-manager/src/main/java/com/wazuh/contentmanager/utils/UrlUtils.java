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

import java.net.URI;
import java.util.Locale;
import java.util.Objects;

/** Shared utility for comparing CTI catalog resource URLs as logical resources. */
public final class UrlUtils {

    private UrlUtils() {}

    /**
     * Returns {@code true} iff {@code a} and {@code b} denote the same logical CTI catalog resource.
     *
     * <p>Comparison is performed on trimmed inputs after URI parsing and normalization. Scheme and
     * host are compared case-insensitively; a single trailing slash on the path is ignored. Falls
     * back to trimmed literal string equality when either input fails to parse as a URI. Two null or
     * blank inputs are considered equal; mixed null/non-null are not.
     *
     * @param a the first URL string (may be {@code null} or blank).
     * @param b the second URL string (may be {@code null} or blank).
     * @return {@code true} if both inputs denote the same logical resource.
     */
    public static boolean sameResource(String a, String b) {
        boolean aBlank = a == null || a.isBlank();
        boolean bBlank = b == null || b.isBlank();
        if (aBlank && bBlank) {
            return true;
        }
        if (aBlank || bBlank) {
            return false;
        }
        String ta = a.trim();
        String tb = b.trim();
        URI ua;
        URI ub;
        try {
            ua = URI.create(ta).normalize();
            ub = URI.create(tb).normalize();
        } catch (IllegalArgumentException e) {
            return ta.equals(tb);
        }
        return canonicalScheme(ua).equals(canonicalScheme(ub))
                && canonicalHost(ua).equals(canonicalHost(ub))
                && ua.getPort() == ub.getPort()
                && canonicalPath(ua).equals(canonicalPath(ub))
                && Objects.equals(ua.getRawQuery(), ub.getRawQuery())
                && Objects.equals(ua.getRawFragment(), ub.getRawFragment());
    }

    private static String canonicalScheme(URI uri) {
        String scheme = uri.getScheme();
        return scheme == null ? "" : scheme.toLowerCase(Locale.ROOT);
    }

    private static String canonicalHost(URI uri) {
        String host = uri.getHost();
        return host == null ? "" : host.toLowerCase(Locale.ROOT);
    }

    private static String canonicalPath(URI uri) {
        String path = uri.getRawPath();
        if (path == null || path.isEmpty()) {
            return "";
        }
        if (path.length() > 1 && path.endsWith("/")) {
            return path.substring(0, path.length() - 1);
        }
        if ("/".equals(path)) {
            return "";
        }
        return path;
    }
}
