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
package com.wazuh.contentmanager.index;

import org.opensearch.client.Client;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.Before;

import org.mockito.Mockito;

import static org.mockito.Mockito.mock;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentIndexTests extends OpenSearchIntegTestCase {
    private ContentIndex contentIndexSpy;

    /**
     * Set up the tests
     *
     * @throws Exception rethrown from parent method
     */
    @Before
    public void setup() throws Exception {
        super.setUp();
        Client client = mock(Client.class);
        ContentIndex contentIndex = new ContentIndex(client);
        contentIndexSpy = Mockito.spy(contentIndex);
    }
}
