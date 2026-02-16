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

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.Assert;

/** Tests for the CategoryFormatter utility class. */
public class CategoryFormatterTests extends OpenSearchTestCase {
    static final String CATEGORY = "category";
    private final ObjectMapper mapper = new ObjectMapper();

    /** Tests that format capitalizes a single-word category. */
    public void testFormatCategoryOneWord() {
        ObjectNode doc = this.mapper.createObjectNode();
        doc.put(CATEGORY, "security");

        String category = CategoryFormatter.format(doc, false);

        Assert.assertEquals("Security", category);
    }

    /** Tests that format converts hyphenated words to title case. */
    public void testFormatCategoryTwoWords() {
        ObjectNode doc = this.mapper.createObjectNode();
        doc.put(CATEGORY, "cloud-services");

        String category = CategoryFormatter.format(doc, false);

        Assert.assertEquals("Cloud Services", category);
    }

    /** Tests that format removes subcategory for three-word categories. */
    public void testFormatCategoryThreeWords() {
        ObjectNode doc = this.mapper.createObjectNode();
        doc.put(CATEGORY, "cloud-services-aws");

        String category = CategoryFormatter.format(doc, false);

        // Assert subcategory is removed
        Assert.assertEquals("Cloud Services", category);
    }

    /** Tests that format returns raw category for threat detectors. */
    public void testFormatCategoryForThreatDetector() {
        ObjectNode doc = this.mapper.createObjectNode();
        doc.put(CATEGORY, "cloud-services");

        //
        String category = CategoryFormatter.format(doc, true);

        // Assert raw category is returned for detectors
        Assert.assertEquals("cloud-services", category);
    }
}
