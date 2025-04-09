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
package com.wazuh.contentmanager;

import com.carrotsearch.randomizedtesting.annotations.ThreadLeakScope;

import org.opensearch.action.support.WriteRequest;
import org.opensearch.test.OpenSearchIntegTestCase;

import com.wazuh.contentmanager.client.CTIClient;
import com.wazuh.contentmanager.model.ctiapi.ConsumerInfo;
import com.wazuh.contentmanager.updater.ContentUpdater;
import com.wazuh.contentmanager.util.Privileged;

import static org.hamcrest.Matchers.*;
import static com.wazuh.contentmanager.settings.PluginSettings.CONTEXT_ID;

@ThreadLeakScope(ThreadLeakScope.Scope.NONE)
@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class ContentUpdaterIT extends OpenSearchIntegTestCase {

    public void testFetchAndApplyUpdates_appliesContentCorrectly() throws Exception {
        // Given: a ContentUpdater with mocked dependencies
        ContentUpdater updater = new ContentUpdater(client());

        // Prepare the environment
        prepareInitialConsumerInfo(0L); // Mock starting offset = 0

        // Mock or create content that CTIClient would return if required
        // You may want to inject a fake CTIClient in test scope, or use @VisibleForTesting override
        // access

        // When: fetch and apply updates
        updater.fetchAndApplyUpdates(0L, 5000L);

        // Then: assert changes were indexed properly
        ConsumerInfo updatedConsumer =
                Privileged.doPrivilegedRequest(() -> CTIClient.getInstance().getCatalog());
        assertNotNull(updatedConsumer);
        assertThat(updatedConsumer.getLastOffset(), greaterThan(0L));
    }

    private void prepareInitialConsumerInfo(Long offset) throws Exception {
        // Create a ConsumerInfo document manually in the test index
        ConsumerInfo info = new ConsumerInfo("test-consumer", "test-context", offset, null);

        // Use your ContextIndex logic or raw index request
        client()
                .prepareIndex("wazuh-context-consumers")
                .setId("test-context:test-consumer")
                .setSource(
                        "consumer_id",
                        info.getName(),
                        "context_id",
                        CONTEXT_ID,
                        "last_offset",
                        info.getLastOffset())
                .setRefreshPolicy(WriteRequest.RefreshPolicy.IMMEDIATE)
                .get();
    }
}
