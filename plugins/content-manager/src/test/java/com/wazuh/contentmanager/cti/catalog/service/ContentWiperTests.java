/*
 * Copyright (C) 2026, Wazuh Inc.
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
package com.wazuh.contentmanager.cti.catalog.service;

import org.opensearch.test.OpenSearchTestCase;
import org.junit.After;
import org.junit.Before;

import java.util.Map;

import com.wazuh.contentmanager.cti.catalog.index.ContentIndex;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;

/** Tests for the wipers that do not need a cluster. */
public class ContentWiperTests extends OpenSearchTestCase {

    @Mock private ContentIndex rules;
    @Mock private ContentIndex decoders;

    private AutoCloseable closeable;

    @Before
    @Override
    public void setUp() throws Exception {
        super.setUp();
        this.closeable = MockitoAnnotations.openMocks(this);
    }

    @After
    @Override
    public void tearDown() throws Exception {
        super.tearDown();
        this.closeable.close();
    }

    /** Every index of the consumer is replaced, not just the first one. */
    public void testClearingIndicesClearsEveryIndexItWasGiven() {
        boolean wiped =
                ContentWiper.clearingIndices(Map.of("rule", this.rules, "decoder", this.decoders)).wipe();

        assertTrue(wiped);
        verify(this.rules).clear();
        verify(this.decoders).clear();
    }

    /**
     * The staging wiper leaves the indices it is handed alone. A swap creates them empty right before
     * the load, and clearing them would recreate them as ordinary indices: visible instead of hidden,
     * and carrying the public alias of the content that is still live.
     */
    public void testNoneLeavesTheIndicesAlone() {
        assertTrue(ContentWiper.none().wipe());

        verifyNoInteractions(this.rules);
        verifyNoInteractions(this.decoders);
    }
}
