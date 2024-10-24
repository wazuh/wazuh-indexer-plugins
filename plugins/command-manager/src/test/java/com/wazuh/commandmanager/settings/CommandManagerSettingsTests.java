/*
 * Copyright OpenSearch Contributors
 * SPDX-License-Identifier: Apache-2.0
 *
 * The OpenSearch Contributors require contributions made to
 * this file be licensed under the Apache-2.0 license or a
 * compatible open source license.
 */
package com.wazuh.commandmanager.settings;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.opensearch.common.settings.KeyStoreWrapper;
import org.opensearch.common.settings.Settings;
import org.opensearch.core.common.settings.SecureString;
import org.opensearch.env.Environment;
import org.opensearch.test.OpenSearchIntegTestCase;
import org.junit.After;
import org.junit.Before;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.AccessControlException;
import java.security.AccessController;
import java.security.GeneralSecurityException;
import java.security.PrivilegedAction;

import org.mockito.InjectMocks;
import org.mockito.Mock;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@OpenSearchIntegTestCase.ClusterScope(scope = OpenSearchIntegTestCase.Scope.SUITE)
public class CommandManagerSettingsTests extends OpenSearchIntegTestCase {
    @Mock private Environment mockEnvironment;

    private final SecureString secureString = new SecureString("dummyPassword".toCharArray());

    @Mock KeyStoreWrapper mockedKeyStoreWrapper;

    @Mock Path mockedPath;

    @InjectMocks private CommandManagerSettings commandManagerSettings;

    private static final Logger log = LogManager.getLogger(CommandManagerSettingsTests.class);

    private static final String KEYSTORE_FILENAME = "opensearch.keystore";

    @Before
    @Override
    public void setUp() throws Exception {
        mockedKeyStoreWrapper = mock(KeyStoreWrapper.class);
        mockEnvironment = mock(Environment.class);
        mockedPath = mock(Path.class);
        super.setUp();
    }

    @After
    public void closeSecureString() {
        // Cleanup if necessary
        secureString.close();
    }

    @AwaitsFix(bugUrl = "")
    public void testKeystoreFileNotExistReturnsNull() {
        Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/").toAbsolutePath();
        Path keystoreFile = Path.of(keyStorePath + "/" + KEYSTORE_FILENAME);
        when(mockEnvironment.configFile()).thenReturn(keystoreFile);

        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<Void>)
                            () -> {
                                when(Files.exists(keyStorePath)).thenReturn(false);
                                when(keyStorePath.toAbsolutePath().toString())
                                        .thenReturn(keyStorePath.toString());

                                CommandManagerSettings result =
                                        CommandManagerSettings.getSettings(mockEnvironment);

                                assertNull(
                                        "Expected settings to be null when keystore file does not exist.",
                                        result);

                                return null;
                            });
        } catch (AccessControlException ignored) {

        }
    }

    @AwaitsFix(bugUrl = "")
    public void testKeystoreFileExistsButLoadReturnsNull() {
        Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/").toAbsolutePath();
        Path keystoreFile = Path.of(keyStorePath + "/" + KEYSTORE_FILENAME);
        when(mockEnvironment.configFile()).thenReturn(keystoreFile);

        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<Void>)
                            () -> {
                                when(Files.exists(keystoreFile)).thenReturn(true);
                                try {
                                    when(KeyStoreWrapper.load(keystoreFile, anyString()))
                                            .thenReturn(null);
                                } catch (IOException e) {

                                }

                                CommandManagerSettings result =
                                        CommandManagerSettings.getSettings(mockEnvironment);

                                assertNull(
                                        "Expected settings to be null when keystore load returns null.",
                                        result);

                                return null;
                            });
        } catch (AccessControlException e) {

        }
    }

    @AwaitsFix(bugUrl = "")
    public void testShouldDecryptKeystoreWhenPasswordIsNull() {
        Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/").toAbsolutePath();
        Path keystoreFile = Path.of(keyStorePath + "/" + KEYSTORE_FILENAME);
        when(mockEnvironment.configFile()).thenReturn(keystoreFile);

        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<Void>)
                            () -> {
                                when(Files.exists(keystoreFile)).thenReturn(true);
                                try {
                                    when(KeyStoreWrapper.load(keystoreFile, anyString()))
                                            .thenReturn(mockedKeyStoreWrapper);

                                } catch (IOException e) {
                                    log.error("Error when tryng to mock load: " + e.getMessage());
                                }

                                try {
                                    doNothing().when(mockedKeyStoreWrapper).decrypt(new char[0]);
                                } catch (GeneralSecurityException
                                        | IOException
                                        | RuntimeException e) {
                                    log.error(
                                            "Error when tryng to mock decrypt: " + e.getMessage());
                                }

                                Settings settingsMock = mock(Settings.class);
                                Settings.Builder builderMock = mock(Settings.Builder.class);
                                when(builderMock.setSecureSettings(mockedKeyStoreWrapper).build())
                                        .thenReturn(settingsMock);
                                // when(Settings.builder().setSecureSettings(mockedKeyStoreWrapper).build()).thenReturn(settingsMock);

                                SecureString authUsername =
                                        new SecureString("userTesting".toCharArray());
                                SecureString authPassword =
                                        new SecureString("passTesting".toCharArray());
                                SecureString uri =
                                        new SecureString("http://localhost".toCharArray());

                                when(CommandManagerSettings.M_API_AUTH_USERNAME.get(any()))
                                        .thenReturn(authUsername);
                                when(CommandManagerSettings.M_API_AUTH_PASSWORD.get(any()))
                                        .thenReturn(authPassword);
                                when(CommandManagerSettings.M_API_URI.get(any())).thenReturn(uri);

                                CommandManagerSettings result =
                                        CommandManagerSettings.getSettings(mockEnvironment);

                                assertNotNull(
                                        "Expected CommandManagerSettings to be created.", result);
                                assertEquals(
                                        "userTesting",
                                        result.getAuthUsername(),
                                        "The username should match the configured value.");
                                assertEquals(
                                        "passTesting",
                                        result.getAuthPassword(),
                                        "The password should match the configured value.");
                                assertEquals(
                                        "http://localhost",
                                        result.getUri(),
                                        "The URI should match the configured value.");

                                return null;
                            });
        } catch (AccessControlException e) {
            log.error("AccesControl Error: " + e.getMessage());
        }
    }

    @AwaitsFix(bugUrl = "")
    public void testShouldDecryptKeystoreWithPassword() {
        Path keyStorePath = Path.of("plugins/command-manager/src/test/resources/").toAbsolutePath();
        Path keystoreFile = Path.of(keyStorePath + "/" + KEYSTORE_FILENAME);
        when(mockEnvironment.configFile()).thenReturn(keystoreFile);

        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<Void>)
                            () -> {
                                when(Files.exists(keystoreFile)).thenReturn(true);
                                try {
                                    when(KeyStoreWrapper.load(keystoreFile, anyString()))
                                            .thenReturn(mockedKeyStoreWrapper);

                                } catch (IOException e) {
                                    log.error("Error when tryng to mock load: " + e.getMessage());
                                }

                                try {
                                    SecureString password =
                                            new SecureString("passwordTest".toCharArray());
                                    doNothing()
                                            .when(mockedKeyStoreWrapper)
                                            .decrypt(password.getChars());
                                } catch (GeneralSecurityException
                                        | IOException
                                        | RuntimeException e) {
                                    log.error(
                                            "Error when tryng to mock decrypt: " + e.getMessage());
                                }

                                Settings settingsMock = mock(Settings.class);
                                Settings.Builder builderMock = mock(Settings.Builder.class);
                                when(builderMock.setSecureSettings(mockedKeyStoreWrapper).build())
                                        .thenReturn(settingsMock);
                                // when(Settings.builder().setSecureSettings(mockedKeyStoreWrapper).build()).thenReturn(settingsMock);

                                SecureString authUsername =
                                        new SecureString("userTesting".toCharArray());
                                SecureString authPassword =
                                        new SecureString("passTesting".toCharArray());
                                SecureString uri =
                                        new SecureString("http://localhost".toCharArray());

                                when(CommandManagerSettings.M_API_AUTH_USERNAME.get(any()))
                                        .thenReturn(authUsername);
                                when(CommandManagerSettings.M_API_AUTH_PASSWORD.get(any()))
                                        .thenReturn(authPassword);
                                when(CommandManagerSettings.M_API_URI.get(any())).thenReturn(uri);

                                CommandManagerSettings result =
                                        CommandManagerSettings.getSettings(mockEnvironment);

                                assertNotNull(
                                        "Expected CommandManagerSettings to be created.", result);
                                assertEquals(
                                        "userTesting",
                                        result.getAuthUsername(),
                                        "The username should match the configured value.");
                                assertEquals(
                                        "passTesting",
                                        result.getAuthPassword(),
                                        "The password should match the configured value.");
                                assertEquals(
                                        "http://localhost",
                                        result.getUri(),
                                        "The URI should match the configured value.");

                                return null;
                            });
        } catch (AccessControlException e) {
            log.error("AccesControl Error: " + e.getMessage());
        }
    }

    @AwaitsFix(bugUrl = "")
    public void testValuesOfGetSettings_keystoreExists() {
        // Set up the mock to return a specific path for the config file
        Path keyStorePath =
                Path.of("command-manager/build/testclusters/integTest-0/config").toAbsolutePath();
        when(mockEnvironment.configFile()).thenReturn(keyStorePath);

        try {
            AccessController.doPrivileged(
                    (PrivilegedAction<Void>)
                            () -> {
                                // Simulate an existing keystore
                                try {
                                    KeyStoreWrapper keyStoreWrapper =
                                            KeyStoreWrapper.load(keyStorePath);

                                    log.info(
                                            "Is keyStoreWrapper loaded? "
                                                    + keyStoreWrapper.isLoaded());

                                    this.commandManagerSettings =
                                            CommandManagerSettings.getSettings(
                                                    mockEnvironment);

                                    assertNotNull(commandManagerSettings);
                                    log.info(
                                            "Plugin settings: {}",
                                            commandManagerSettings
                                                    .toString()); // verify(keyStoreWrapper,
                                    // times(1)).decrypt(secureString.getChars());
                                } catch (IOException e) {
                                    log.error("IO Error: " + e.getMessage());
                                }
                                return null;
                            });
        } catch (AccessControlException e) {
            log.error("AccesControl Error: " + e.getMessage());
        }
    }
}
