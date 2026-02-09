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
package com.wazuh.contentmanager.cti.catalog.utils;

import com.google.gson.JsonObject;
import org.opensearch.core.common.Strings;

import java.util.Arrays;

import com.wazuh.contentmanager.utils.Constants;

/**
 * Utility class for formatting category strings from CTI documents. Transforms raw category
 * identifiers into human-readable format.
 */
public class CategoryFormatter {

    private CategoryFormatter() {}

    /**
     * Retrieves the integration category from the document and returns a formatted string. For
     * detectors, returns the raw category unchanged. For other uses, transforms hyphenated categories
     * into capitalized space-separated words.
     *
     * @param doc The JSON document containing the category field.
     * @param isDetector If true, returns the raw category without formatting.
     * @return The formatted category string, or the raw category for detectors.
     */
    public static String format(JsonObject doc, boolean isDetector) {
        String rawCategory = doc.get(Constants.KEY_CATEGORY).getAsString();

        // Do not pretty print category for detectors
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
