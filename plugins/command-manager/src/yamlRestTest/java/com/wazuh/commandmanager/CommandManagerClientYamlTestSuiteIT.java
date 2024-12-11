/*
 * Copyright (C) 2024 Wazuh
 * This file is part of Wazuh Indexer Plugins, which are licensed under the AGPLv3.
 *  See <https://www.gnu.org/licenses/agpl-3.0.txt> for the full text of the license.
 */
package com.wazuh.commandmanager;

import com.carrotsearch.randomizedtesting.annotations.Name;
import com.carrotsearch.randomizedtesting.annotations.ParametersFactory;

import org.opensearch.test.rest.yaml.ClientYamlTestCandidate;
import org.opensearch.test.rest.yaml.OpenSearchClientYamlSuiteTestCase;

public class CommandManagerClientYamlTestSuiteIT extends OpenSearchClientYamlSuiteTestCase {

    public CommandManagerClientYamlTestSuiteIT(
            @Name("yaml") ClientYamlTestCandidate testCandidate) {
        super(testCandidate);
    }

    @ParametersFactory
    public static Iterable<Object[]> parameters() throws Exception {
        return OpenSearchClientYamlSuiteTestCase.createParameters();
    }
}
