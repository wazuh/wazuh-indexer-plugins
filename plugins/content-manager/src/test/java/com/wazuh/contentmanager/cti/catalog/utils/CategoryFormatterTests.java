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
import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

/** Tests for the CategoryFormatter utility class. */
public class CategoryFormatterTests extends OpenSearchTestCase {
    static final String CATEGORY = "category";

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

        //
        String category = CategoryFormatter.format(doc, true);

        // Assert raw category is returned for detectors
        Assert.assertEquals("cloud-services", category);
    }
}
