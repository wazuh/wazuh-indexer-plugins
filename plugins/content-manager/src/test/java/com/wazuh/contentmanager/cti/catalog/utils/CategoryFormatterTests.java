package com.wazuh.contentmanager.cti.catalog.utils;

import com.google.gson.JsonObject;
import org.junit.Assert;
import org.junit.Test;
import org.opensearch.test.OpenSearchTestCase;

import static com.wazuh.contentmanager.cti.catalog.utils.CategoryFormatter.CATEGORY;

/**
 * Tests for the CategoryFormatter utility class.
 */
public class CategoryFormatterTests extends OpenSearchTestCase {

    public void testFormatCategoryOneWord() {
        JsonObject doc = new JsonObject();
        doc.addProperty(CATEGORY, "security");

        String category = CategoryFormatter.format(doc, false);

        Assert.assertEquals("Security", category);
    }

    public void testFormatCategoryTwoWords() {
        JsonObject doc = new JsonObject();
        doc.addProperty(CATEGORY, "cloud-services");

        String category = CategoryFormatter.format(doc, false);

        Assert.assertEquals("Cloud Services", category);
    }

    public void testFormatCategoryThreeWords() {
        JsonObject doc = new JsonObject();
        doc.addProperty(CATEGORY, "cloud-services-aws");

        String category = CategoryFormatter.format(doc, false);

        // Assert subcategory is removed
        Assert.assertEquals("Cloud Services", category);
    }

    public void testFormatCategoryForThreatDetector() {
        JsonObject doc = new JsonObject();
        doc.addProperty(CATEGORY, "cloud-services");

        String category = CategoryFormatter.format(doc, true);

        // Assert raw category is returned for detectors
        Assert.assertEquals("cloud-services", category);
    }
}
