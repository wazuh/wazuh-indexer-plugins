/*
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;

import com.wazuh.commandmanager.CommandManagerSettingsException;
import org.junit.After;
import org.junit.Before;
import org.junit.Ignore;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.opensearch.common.settings.KeyStoreWrapper;
import org.opensearch.common.settings.SecureSettings;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchIntegTestCase;

import java.io.File;
import java.io.IOException;
import java.lang.reflect.Field;
import java.nio.file.Path;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;

import static org.mockito.Mockito.*;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class PluginSettingsTests extends OpenSearchIntegTestCase {


    @Mock
    private Environment mockEnvironment;


    private final SecureString secureString = new SecureString("dummyPassword".toCharArray());

    @Mock
    KeyStoreWrapper mockedKeyStoreWrapper;

    @InjectMocks
    private PluginSettings pluginSettings;

    @Before
    @Override
    public void setUp() throws Exception {
        mockedKeyStoreWrapper = mock(KeyStoreWrapper.class);
        mockEnvironment = mock(Environment.class);
        // Instantiate PluginSettings
        pluginSettings = PluginSettings.getInstance();
        pluginSettings.setEnvironment(mockEnvironment);
        super.setUp();
    }

    @After
    public void closeSecureString() {
        // Cleanup if necessary
        secureString.close();
    }

    public void testLoadSecureSettings_keystoreNotExist() throws Exception {
        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<Void>) () -> {
                        // Set up the mock to return a specific path for the config file
                       Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/").toAbsolutePath();
                       when(mockEnvironment.configFile()).thenReturn(keyStorePath);

                        //Invoke the method under test and Check that the keystore doesn't exist
                        SecureSettings result = null;
                        try {
                            result = this.pluginSettings.loadSecureSettings(this.secureString);
                        } catch (CommandManagerSettingsException | GeneralSecurityException | AccessControlException e) {
                            System.out.println(e.getMessage());
                        }

                        KeyStoreWrapper keyStoreWrapper = this.pluginSettings.getKeyStoreWrapper();

                        //assertNotNull(result);
                        // Verify that the methods were called on the spy
                        boolean isLoaded = keyStoreWrapper.isLoaded();
                        assertTrue(isLoaded);

                        try {
//                            verify(mockedKeyStoreWrapper, only()).save(any(Path.class), new char[]{anyChar()});
                          //  verify(mockedKeyStoreWrapper).decrypt(any());
                        } catch (Exception e) {
                            throw new RuntimeException(e);
                        }

                        // Mock the static method KeyStoreWrapper.load(...)
       /* try (MockedStatic<KeyStoreWrapper> mockedKeyStore = Mockito.mockStatic(KeyStoreWrapper.class)) {
            mockedKeyStore.when(() -> KeyStoreWrapper.load(any(Path.class), anyString())).thenReturn(null);

            // Create a spy for KeyStoreWrapper to verify save method call
            KeyStoreWrapper spyKeyStore = Mockito.spy(KeyStoreWrapper.create());

            //Invoke the method under test and Check that the keystore doesn't exist
            SecureSettings result = this.pluginSettings.loadSecureSettings(this.secureString);

            assertNotNull(result);

            // Verify that load() was called
            mockedKeyStore.verify(() -> KeyStoreWrapper.load(any(Path.class), anyString()), times(1));

            // Verify that save() was called once on the KeyStoreWrapper spy
            Mockito.verify(spyKeyStore, times(1)).save(any(Path.class), any(char[].class));
        }
        */
                        return null;
                    }
            );
        }catch(AccessControlException e){

        }


    }

    public void testLoadSecureSettings_keystoreExists() throws Exception {
        // Set up the mock to return a specific path for the config file
        Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/").toAbsolutePath();
        when(mockEnvironment.configFile()).thenReturn(keyStorePath);
        System.out.println("ACAAAAAAAAAAAAAAA Attempting to read file: " + new File("plugins/command-manager/src/test/resources/wazuh-indexer.keystore.json").getAbsolutePath());

        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<Void>) () -> {
                        // Simulate an existing keystore
                        KeyStoreWrapper keyStoreWrapper = this.pluginSettings.getKeyStoreWrapper();
                        try {
                            keyStoreWrapper = KeyStoreWrapper.load(keyStorePath, "wazuh-indexer.keystore.json");
                            when(KeyStoreWrapper.load(any(), any())).thenReturn(keyStoreWrapper);

                            // Load secure settings
                            SecureSettings result = this.pluginSettings.loadSecureSettings(secureString);

                            assertNotNull(result);
                           // verify(keyStoreWrapper, times(1)).decrypt(secureString.getChars());
                        } catch (IOException | CommandManagerSettingsException | GeneralSecurityException e) {
                            throw new RuntimeException(e);
                        }
                        return null;
                    }
            );
        }catch(AccessControlException e){

        }
    }
}
