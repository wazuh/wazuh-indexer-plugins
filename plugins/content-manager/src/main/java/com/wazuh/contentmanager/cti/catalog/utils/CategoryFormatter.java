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

import com.google.gson.JsonObject;
import org.opensearch.core.common.Strings;

import java.util.Arrays;

/** Formats category strings from CTI documents. */
public class CategoryFormatter {
    static final String CATEGORY = "category";

    /**
     * Retrieves the integration category from the document and returns a cleaned up string.
     *
     * @param doc Json document
     * @return capitalized space-separated string
     */
    public static String format(JsonObject doc, boolean isDetector) {
        String rawCategory = doc.get(CATEGORY).getAsString();

        // Do not pretty print category f
        if (isDetector) {
            return rawCategory;
        }

        // TODO remove when CTI applies the changes to the categorization.
        // Remove subcategory. Currently only cloud-services has subcategories (aws, gcp, azure).
        if (rawCategory.contains("cloud-services")) {
            rawCategory = rawCategory.substring(0, 14);
        }
        return Arrays.stream(rawCategory.split("-"))
                .reduce("", (current, next) -> current + " " + Strings.capitalize(next))
                .trim();
    }
}
