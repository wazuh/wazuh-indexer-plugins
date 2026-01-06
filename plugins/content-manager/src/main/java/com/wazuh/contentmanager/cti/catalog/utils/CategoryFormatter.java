package com.wazuh.contentmanager.cti.catalog.utils;

import java.util.Arrays;

import org.opensearch.core.common.Strings;

import com.google.gson.JsonObject;

/**
 * Formats category strings from CTI documents.
 */
public class CategoryFormatter {
    static final String CATEGORY = "category";

    /**
     * Retrieves the integration category from the document and returns a cleaned up string.
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
        return Arrays.stream(
            rawCategory
                .split("-"))
                .reduce("", (current, next) -> current + " " + Strings.capitalize(next))
                .trim();
    }
}