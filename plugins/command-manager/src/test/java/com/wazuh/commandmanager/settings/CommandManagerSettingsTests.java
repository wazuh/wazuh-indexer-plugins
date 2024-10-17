/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.opensearch.common.settings.KeyStoreWrapper;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.IOException;
import java.nio.file.Path;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.PrivilegedAction;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class CommandManagerSettingsTests extends OpenSearchIntegTestCase{
    @Mock
    private Environment mockEnvironment;


    private final SecureString secureString = new SecureString("dummyPassword".toCharArray());

    @Mock
    KeyStoreWrapper mockedKeyStoreWrapper;

    private CommandManagerSettings commandManagerSettings;

    private static final Logger log = LogManager.getLogger(CommandManagerSettingsTests.class);


    @Before
    @Override
    public void setUp() throws Exception {
        mockedKeyStoreWrapper = mock(KeyStoreWrapper.class);
        mockEnvironment = mock(Environment.class);
        super.setUp();
    }

    @After
    public void closeSecureString() {
        // Cleanup if necessary
        secureString.close();
    }

    public void testGetSettings_keystoreExists() throws Exception {
        // Set up the mock to return a specific path for the config file
        Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/").toAbsolutePath();
        when(mockEnvironment.configFile()).thenReturn(keyStorePath);

        //logger.error(String.format(" Attempting to read file: %s%s", keyStorePath,"wazuh-indexer.keystore.json"));

        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<Void>) () -> {
                        // Simulate an existing keystore
                        try {
                            KeyStoreWrapper keyStoreWrapper = KeyStoreWrapper.load(keyStorePath, "wazuh-indexer.keystore.json");
                            when(KeyStoreWrapper.load(any(), any())).thenReturn(keyStoreWrapper);
                            log.warn("test INSIDE+EE");

                            this.commandManagerSettings = CommandManagerSettings.getSettings(mockEnvironment);

                            assertNotNull(commandManagerSettings);
                            log.warn("keystore INSIDE"+commandManagerSettings.keystore);
                            // verify(keyStoreWrapper, times(1)).decrypt(secureString.getChars());
                        } catch (IOException e) {
                            log.warn("ERROR TEST: "+e.getMessage());
                        }
                        log.warn("RETURN");
                        return null;
                    }
            );
        }catch(AccessControlException e){

        }
    }
}
